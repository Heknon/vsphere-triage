"""The composite diagnoses: one call that runs every check, in a fixed order, and says why.

The order is the one a person would follow once they have learned it the hard
way, and the server follows it so the model does not have to remember it:

1. the machine: power, Tools, heartbeat, a pending question, CPU use;
2. CPU: the VM's ready time and the host's demand against its capacity;
3. storage: the datastores' latency, and whether the device or the host's queue;
4. the rest of the environment: are the healthy VMs elsewhere?;
5. the guest: how far the boot got (`vmware.log`), the serial console (EMS),
   and the screen.

Each piece that cannot be read says so and the rest go on; a diagnosis never
fails because the console endpoint or a counter is missing. All of it is
blocking and runs in one worker thread per vCenter call.
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from pyVmomi import vim, vmodl

from vsphere_triage import capabilities
from vsphere_triage.checks import (
    BLOCKED_ON_QUESTION,
    BOOT_LOOP,
    BOOTED_NOT_UP,
    BUSY_NOT_UP,
    CPU_LIMITED,
    HEALTHY,
    HEARTBEAT_INTERMITTENT,
    HOST_MEMORY_PRESSURE,
    HOST_NOT_CONNECTED,
    HUNG,
    INACCESSIBLE,
    MEMORY_LIMITED,
    MEMORY_RECLAIMED,
    NO_TOOLS,
    OFF,
    PAUSED,
    RESET_EVENTS,
    SUSPENDED,
    TOOLS_FLAPPING,
    Verdict,
    classify,
    count_states,
    latest_reboot_by_vm,
    resets_by_vm,
)
from vsphere_triage.console import read_captures
from vsphere_triage.contention import hosts_cpu, storage, vm_cpu
from vsphere_triage.hostsensors import classify_sensors, read_sensors
from vsphere_triage.inventory import (
    DEVICE_PATH,
    VM_PATHS,
    FolderFacts,
    HostFacts,
    VmFacts,
    alarm_names,
    find_environment,
    read_datastores,
    read_folders,
    read_hosts,
    set_effective_boot,
    snapshot_usage,
    vm_facts,
)
from vsphere_triage.vcenter import QUERY_EVENTS_CAP, REALTIME_SPAN, VSphereError, parse_datastore_path
from vsphere_triage.vmlog import boot_timeline, grep, parse_lines, read_serial

if TYPE_CHECKING:
    from collections.abc import Callable

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterSession

# The causes a diagnosis weighs. Results name them by these exact strings.
CPU = "CPU starvation (ESXi overcommit)"
STORAGE = "storage latency (datastore / PowerFlex)"
BOOT_STORM = "linked-clone boot storm on a shared base disk"
WINDOWS_CRASH = "Windows crashed (stop error)"
KERNEL_ERROR = "the guest kernel reported an error"
STILL_WORKING = "Windows still working through boot (slow, not hung)"
CANNOT_BOOT = "the guest cannot boot"
TOOLS_DID_NOT_START = "the guest booted; Tools did not start"
EARLY_HANG = "the guest hung early in boot"
BOOT_LOOP_CAUSE = "the VM is in a boot loop (it keeps resetting)"
VM_FAULT = "the virtual machine faulted"
TOOLS_FLAPPING_CAUSE = "Tools flapping"
INACCESSIBLE_CAUSE = "vCenter cannot reach the VM"
QUESTION = "a pending VM question blocks it"
HARDWARE = "a virtual device is blocking or breaking the boot"
SNAPSHOT = "snapshots are consuming disk and slowing I/O"
CPU_LIMIT_CAUSE = "throttled by a configured CPU limit (not host starvation)"
MEMORY_LIMIT_CAUSE = "a configured memory limit is forcing reclamation"
PAUSED_CAUSE = "the VM is paused"
MEMORY = "memory pressure (the host ballooning or swapping the VM)"
DATASTORE_CAPACITY = "its datastore is full or unreachable (APD/PDL)"
HOST_DISCONNECTED = "its ESXi host is not connected to vCenter"
HOST_HARDWARE = "its ESXi host reports failing hardware"

DIAGNOSE_PATHS = (
    *VM_PATHS,
    DEVICE_PATH,
    "config.files.vmPathName",
    "config.files.logDirectory",
    "snapshot",
    "layoutEx",
)
LAYOUT_TTL_SECONDS = 60.0
EVENTS_KEPT = 40
HOST_LOG_LINES = 2000
SERIAL_BYTES = 256 * 1024
ROTATED_LOG_BYTES = 512 * 1024
STORAGE_HOST_LOG = (
    r"(?i)(performance has deteriorated|latency|apd|pdl|all paths down|permanent device loss|"
    r"lost access|scsi.*(abort|reset|fail)|path.*(dead|down|fail)|nmp.*fail|i/o error)"
)


# -- reading ---------------------------------------------------------------------


class Layout:
    """Folders, hosts and datastores of one vCenter, read once a minute at most."""

    _cache: dict[str, tuple[float, Layout]] = {}  # noqa: RUF012 - a process-wide cache by design

    def __init__(self, session: VCenterSession) -> None:
        """Read the three, now."""
        self.folders: dict[str, FolderFacts] = read_folders(session)
        self.hosts: dict[str, HostFacts] = read_hosts(session)
        self.datastores: dict[str, dict[str, Any]] = read_datastores(session)

    @classmethod
    def of(cls, session: VCenterSession) -> Layout:
        """The cached layout of this session's vCenter, re-read when older than a minute."""
        key = f"{session.vcenter.name}:{id(session)}:{session.generation}"
        hit = cls._cache.get(key)
        if hit and time.monotonic() - hit[0] < LAYOUT_TTL_SECONDS:
            return hit[1]
        layout = cls(session)
        now = time.monotonic()
        # Drop expired entries (older sessions and generations) so a long-running
        # server's cache does not grow with every re-login.
        for stale in [name for name, (at, _) in cls._cache.items() if now - at >= LAYOUT_TTL_SECONDS]:
            cls._cache.pop(stale, None)
        cls._cache[key] = (now, layout)
        return layout


def read_vms(
    session: VCenterSession,
    layout: Layout,
    *,
    objects: list[Any] | None = None,
    root: Any = None,
) -> list[tuple[VmFacts, dict[str, Any]]]:
    """VMs with everything a diagnosis reads, and the raw rows for file paths."""
    now = session.now()
    rows = session.retrieve(vim.VirtualMachine, DIAGNOSE_PATHS, objects=objects, root=root)
    names = alarm_names(session, rows)
    return [
        (
            vm_facts(
                session.vcenter.name,
                row,
                now,
                layout.folders,
                layout.hosts,
                layout.datastores,
                with_devices=True,
                alarms=names,
            ),
            row,
        )
        for row in rows
    ]


def _in_environment(layout: Layout, vm: VmFacts, env_id: str) -> bool:
    """Whether a folder named exactly `env_id` holds the VM, directly or above it."""
    wanted = env_id.strip().lower()
    current = layout.folders.get(vm.folder_moref or "")
    seen: set[str] = set()
    while current is not None and current.moref not in seen:
        if current.name.lower() == wanted:
            return True
        seen.add(current.moref)
        current = layout.folders.get(current.parent_moref or "")
    return False


def locate(  # noqa: C901, PLR0911, PLR0912 - one lookup, each way it can fail beside it
    session: VCenterSession,
    settings: Settings,
    *,
    env_id: str | None,
    vm_name: str | None,
    moref: str | None,
    strict: bool = False,
) -> dict[str, Any]:
    """Find one VM by moref, or by its environment and its name inside it.

    Never by name alone: the name is reused by later environments. Returns the
    VM, or why it could not be found and what was found instead.

    `strict=True` is for the tools that act on a VM (a guest command, a reboot, a
    reset): a moref whose name differs from the `vm_name` given is refused rather
    than noted, and the environment folder and the VM name must match exactly, so
    a typo never lands the action on a neighbouring VM. A moref alone is refused
    too: morefs repeat across vCenters (vm-1001 on each), so one paired with the
    wrong vCenter would act on some other VM; its name must come with it.
    """
    if strict and moref and not vm_name:
        return {
            "found": False,
            "reason": "acting on a VM needs its name with its moref (morefs repeat across vCenters); "
            "pass vm_name too, so the right VM is checked before anything is run or sent",
        }
    layout = Layout.of(session)
    if moref:
        found = read_vms(session, layout, objects=[session.reference("VirtualMachine", moref)])
        if not found:
            return {
                "found": False,
                "reason": f"{moref} does not exist on {session.vcenter.name} (destroyed?)",
            }
        vm, row = found[0]
        if vm_name and vm.name != vm_name:
            if strict:
                return {
                    "found": False,
                    "reason": f"{moref} is named {vm.name!r}, not {vm_name!r}; refusing to act on a VM "
                    "whose name does not match — check the moref",
                }
            vm.notes.append(f"asked for {vm_name!r} but {moref} is named {vm.name!r}")
        if strict and env_id and not _in_environment(layout, vm, env_id):
            # Names repeat across environments, so the name alone does not prove a
            # stale moref is the VM meant: its folder chain must hold the environment.
            return {
                "found": False,
                "reason": f"{moref} is not inside an environment folder named {env_id!r} (it is in "
                f"{vm.folder_path or 'no known folder'}); refusing to act on it — check the moref",
            }
        return {"found": True, "vm": vm, "row": row, "layout": layout}
    if not env_id or not vm_name:
        return {
            "found": False,
            "reason": (
                "give either a moref, or both env_id and vm_name: a name is reused by later "
                "environments, so it means nothing outside its environment folder. Without the "
                "env id, find_environment(env_id) or a scan lists the VMs with their morefs"
            ),
        }
    folders = find_environment(layout.folders, env_id, settings.env_parent_hints)
    if not folders:
        return {
            "found": False,
            "reason": f"no folder on {session.vcenter.name} is named {env_id!r} or contains it "
            "(the environment may have been destroyed, or be on another vCenter)",
        }
    exact = [folder for folder in folders if folder.name.lower() == env_id.strip().lower()]
    if strict and not exact:
        return {
            "found": False,
            "reason": f"no folder is named exactly {env_id!r} (only folders containing it); refusing to act "
            "on a VM found by a partial environment id — give the full id or the moref",
            "candidates": [folder.path for folder in folders[:MAX_CANDIDATE_FOLDERS]],
        }
    candidates = exact or folders
    if len(candidates) > MAX_CANDIDATE_FOLDERS:
        # A short id contained in hundreds of folder names: each would be read with the
        # heavy diagnosis paths. Ask for the exact id rather than read them all.
        return {
            "found": False,
            "reason": f"{len(candidates)} folders contain {env_id!r} and none is named exactly that; "
            "give the full environment id, or the VM's moref",
            "candidates": [folder.path for folder in candidates[:MAX_CANDIDATE_FOLDERS]],
        }
    matches = []
    seen: set[str] = set()
    for folder in candidates:
        root = session.reference("Folder", folder.moref)
        for vm, row in read_vms(session, layout, root=root):
            # Nested matching folders read one VM twice; it is still one VM.
            if vm.moref in seen:
                continue
            if vm.name == vm_name or (not strict and vm.name.lower() == vm_name.lower()):
                seen.add(vm.moref)
                matches.append((folder, vm, row))
    if len(matches) == 1:
        folder, vm, row = matches[0]
        # Nested matching folders: name the folder the VM actually sits in.
        folder = next((item for item in candidates if item.moref == vm.folder_moref), folder)
        if len(candidates) > 1:
            vm.notes.append(f"{len(candidates)} folders match {env_id!r}; the VM was found in {folder.path}")
        return {"found": True, "vm": vm, "row": row, "layout": layout, "folder": folder}
    if len(matches) > 1:
        return {
            "found": False,
            "reason": f"{len(matches)} VMs named {vm_name!r} under folders matching {env_id!r}; "
            "pass the moref of the one meant",
            "candidates": [vm.identity() for _, vm, _ in matches],
        }
    names = []
    for folder in candidates[:3]:
        root = session.reference("Folder", folder.moref)
        names.extend(vm.name for vm, _ in read_vms(session, layout, root=root))
    return {
        "found": False,
        "reason": f"no VM named {vm_name!r} in the environment folder(s) "
        + ", ".join(folder.path for folder in candidates[:3]),
        "vms_in_environment": sorted(names)[:50],
    }


# The most folders a non-exact environment id is looked for in.
MAX_CANDIDATE_FOLDERS = 10


def window(now: datetime, boot: datetime | None) -> tuple[datetime, datetime]:
    """The window a VM's boot is judged over: from just before it booted.

    Inside vCenter's realtime hour the window runs to now; a boot older than
    that is judged on its first half-hour, from the historical rollup.
    """
    if boot is None:
        return now - timedelta(minutes=30), now
    if now - boot <= REALTIME_SPAN - timedelta(minutes=2):
        return boot - timedelta(minutes=2), now
    return boot - timedelta(minutes=5), min(now, boot + timedelta(minutes=30))


def piece(name: str, work: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run one part of a diagnosis; if it fails, say what failed and go on."""
    try:
        return work()
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and run the diagnosis again
    except VSphereError as error:
        return {"available": False, "reason": str(error)}
    except Exception as error:  # noqa: BLE001 - a missing piece must not fail the whole
        return {"available": False, "reason": f"{name} not read: {type(error).__name__}: {error}"}


def summarize_events(events: list[Any]) -> list[dict[str, Any]]:
    """Events as a reader needs them: when, what, who, the message."""
    return [
        {
            "time": event.createdTime,
            "type": type(event).__name__.rsplit(".", 1)[-1],
            "user": getattr(event, "userName", None) or None,
            "message": (getattr(event, "fullFormattedMessage", None) or "").strip()[:300],
        }
        for event in events[-EVENTS_KEPT:]
    ]


def vm_folder(row: dict[str, Any], vm: VmFacts) -> str | None:
    """The datastore folder holding the VM's `.vmx` and logs."""
    log_directory = row.get("config.files.logDirectory")
    if log_directory:
        return str(log_directory).rstrip("/")
    vmx = row.get("config.files.vmPathName")
    if vmx and "/" in vmx:
        return vmx.rsplit("/", 1)[0]
    if vm.disk_chain:
        own = vm.disk_chain[0][0]
        return own.rsplit("/", 1)[0] if "/" in own else None
    return None


# Enough of the end of vmware.log to hold the last boot's start on a VM that has
# been stuck a while; a scan reads this much for each suspect VM.
LOG_REBOOT_BYTES = 512 * 1024


# Sensor kinds whose failure slows the VMs on a host (throttling, memory errors).
_SLOWING_SENSORS = ("temperature", "temp", "processor", "cpu", "memory")


def _slows_vms(sensor: dict[str, Any]) -> bool:
    """Whether a failing sensor is of a kind that slows the host's VMs."""
    text = f"{sensor.get('type') or ''} {sensor.get('name') or ''}".lower()
    return any(kind in text for kind in _SLOWING_SENSORS)


def boot_from_vmware_log(
    session: VCenterSession,
    vm: VmFacts,
    row: dict[str, Any],
    max_bytes: int = LOG_REBOOT_BYTES,
    *,
    timeout_seconds: float | None = None,
) -> datetime | None:
    """When the last boot in the VM's `vmware.log` began, or None if it cannot be read.

    A reboot started inside the guest logs no vCenter event and leaves
    runtime.bootTime at the power-on; the VMX's own log still records the reset.
    """
    folder = vm_folder(row, vm)
    datacenter = vm.datacenter_path or vm.datacenter
    if folder is None or datacenter is None:
        return None
    found = session.read_datastore_file(
        datacenter, f"{folder}/vmware.log", max_bytes, timeout_seconds=timeout_seconds, ceiling=max_bytes * 4
    )
    if found.status != 200:  # noqa: PLR2004
        return None
    timeline = boot_timeline(parse_lines(found.text))
    return timeline.get("boot_started") if timeline.get("boot_found") else None


def _read_reason(name: str, status: int, folder: str) -> str:
    """Why a datastore file read did not return a body, worded for a reader."""
    where = f" at {folder}/{name}" if folder else ""
    if status == 416:  # noqa: PLR2004
        return (
            f"{name} is larger than VSPHERE_MAX_DOWNLOAD_BYTES and this vCenter did not honor a "
            f"range request, so its end could not be read{where}; raise the cap to read it"
        )
    if 300 <= status < 400:  # noqa: PLR2004
        return (
            f"{name}: vCenter redirected the request (HTTP {status}){where}; not followed because it "
            "leaves this vCenter's origin (a known real-vCenter behaviour to confirm)"
        )
    if status == 404:  # noqa: PLR2004
        return f"{name} not found{where}"
    return f"{name} not readable (HTTP {status}){where}"


def read_logs(
    session: VCenterSession, settings: Settings, vm: VmFacts, row: dict[str, Any]
) -> dict[str, Any]:
    """The current `vmware.log` (its end), the boot timeline from it, and the previous log."""
    folder = vm_folder(row, vm)
    datacenter = vm.datacenter_path or vm.datacenter
    if folder is None or datacenter is None:
        return {"available": False, "reason": "the VM's datastore folder or datacenter is not known"}
    current = session.read_datastore_file(datacenter, f"{folder}/vmware.log", settings.max_log_bytes)
    if current.status != 200:  # noqa: PLR2004
        return {"available": False, "reason": _read_reason("vmware.log", current.status, folder)}
    lines = parse_lines(current.text)
    timeline = boot_timeline(lines)
    tools_changes = timeline.get("annotations", {}).get("tools_state", {}).get("count", 0)
    rotated = piece("log listing", lambda: {"files": _list_logs(session, vm, folder)})
    previous = session.read_datastore_file(datacenter, f"{folder}/vmware-1.log", ROTATED_LOG_BYTES)
    previous_lines = parse_lines(previous.text) if previous.status == 200 else []  # noqa: PLR2004
    previous_matches, previous_total = grep(previous_lines, None, limit=20)
    relevant, total = grep(lines, None, limit=40)
    return {
        "available": True,
        "path": f"{folder}/vmware.log",
        "bytes": current.size,
        "read_only_the_end": current.truncated,
        "timeline": timeline,
        "relevant_lines": [line.as_dict() for line in relevant],
        "relevant_lines_total": total,
        "tools_state_changes": tools_changes,
        "log_files": rotated.get("files", rotated),
        "previous_log": {
            "path": f"{folder}/vmware-1.log",
            "available": previous.status == 200,  # noqa: PLR2004
            "relevant_lines": [line.as_dict() for line in previous_matches],
            "relevant_lines_total": previous_total,
        },
    }


def _list_logs(session: VCenterSession, vm: VmFacts, folder: str) -> list[dict[str, Any]]:
    """The VM's log files, newest first: vmware.log, then vmware-1.log and older.

    The datastore is chosen from the VM's own datastores by name — a tiny set,
    so the datastore-name collision across datacenters does not bite here.
    """
    datastore, _ = parse_datastore_path(folder)
    stores = Layout.of(session).datastores
    own = [stores[m] for m in vm.datastore_morefs if m in stores and stores[m].get("name") == datastore]
    if not own:
        return []
    files = session.list_folder(own[0]["_ref"], folder, ["vmware*.log"])
    return sorted(files, key=lambda item: (item["name"] != "vmware.log", item["name"]))


def read_serial_files(session: VCenterSession, vm: VmFacts, *, tail_lines: int = 40) -> dict[str, Any]:
    """The VM's serial console files: Windows EMS or a Linux kernel console, if it has one."""
    if not vm.serial_files:
        return {
            "available": False,
            "reason": "the VM has no serial port writing to a file, so there is no EMS or "
            "kernel console output to read; the console screenshot is the guest's evidence",
        }
    datacenter = vm.datacenter_path or vm.datacenter
    if datacenter is None:
        return {"available": False, "reason": "the VM's datacenter is not known"}
    files = []
    for path in vm.serial_files:
        try:
            parse_datastore_path(path)
        except ValueError:
            files.append({"path": path, "available": False, "reason": "not a datastore path"})
            continue
        read = session.read_datastore_file(datacenter, path, SERIAL_BYTES)
        if read.status != 200:  # noqa: PLR2004
            files.append({"path": path, "available": False, "reason": _read_reason(path, read.status, "")})
            continue
        files.append(
            {"path": path, "available": True, "truncated": read.truncated}
            | read_serial(read.text, tail_lines=tail_lines)
        )
    return {"available": any(item.get("available") for item in files), "files": files}


def read_console(
    session: VCenterSession, settings: Settings, vm: VmFacts, *, captures: int, interval_seconds: float
) -> dict[str, Any]:
    """Screenshots of the console, reduced to words."""
    if not vm.powered_on:
        return {"available": False, "reason": "the VM is not powered on; there is no console"}
    images = []
    for index in range(max(1, captures)):
        if index:
            time.sleep(interval_seconds)
        status, body, _ = session.screenshot(vm.moref)
        if status != 200:  # noqa: PLR2004
            return {
                "available": False,
                "reason": f"the console endpoint answered HTTP {status}"
                + (" (a simulator has none)" if status == 404 else ""),  # noqa: PLR2004
            }
        images.append(body)
    thresholds = settings.thresholds
    # `_last_capture` is the image analysed last, for a caller that shows it; the
    # leading underscore keeps it out of every JSON result.
    return {
        "available": True,
        "interval_seconds": interval_seconds,
        "_last_capture": images[-1],
    } | read_captures(
        images,
        black_fraction=thresholds.console_black_fraction,
        frozen_difference=thresholds.console_frozen_difference,
    )


def read_host_storage_log(session: VCenterSession, host: HostFacts) -> dict[str, Any]:
    """The storage lines of a host's `vmkernel` log, from its last few thousand lines."""
    log = session.host_log(session.reference("HostSystem", host.moref), "vmkernel", HOST_LOG_LINES)
    if not log.get("available"):
        return log
    lines = parse_lines("\n".join(log["lines"]), first_number=log["line_start"])
    matched, total = grep(lines, STORAGE_HOST_LOG, limit=30)
    return {
        "available": True,
        "host": host.name,
        "lines_read": len(lines),
        "storage_lines_total": total,
        "storage_lines": [line.as_dict() for line in matched],
    }


# -- judging ---------------------------------------------------------------------


def environment_pattern(
    vm: VmFacts, peers: list[tuple[VmFacts, Verdict]], *, about_vm: bool = True
) -> dict[str, Any]:
    """How the rest of the VM's environment is doing, and where its healthy VMs are.

    `about_vm=False` is the environment-wide view (diagnose_environment), where
    `vm` only names the folder and no finding speaks of "this VM".
    """
    # Healthy is the complement of abnormal, not a separate HEALTHY/BOOTING test:
    # a VM that is HEALTHY but carries a trouble flag (a boot loop, a lost host) is
    # abnormal, and must not also be counted among the healthy, or one VM lands on
    # both sides. Context flags (long_running, an alarm) leave a VM healthy here.
    abnormal = [(peer, verdict) for peer, verdict in peers if verdict.abnormal]
    healthy = [(peer, verdict) for peer, verdict in peers if not verdict.abnormal]
    result: dict[str, Any] = {
        "folder": vm.folder_path,
        "vms": len(peers),
        "counts_by_state": count_states({peer.moref: verdict for peer, verdict in peers}),
        "abnormal_hosts": dict(Counter(peer.host for peer, _ in abnormal)),
        "healthy_hosts": dict(Counter(peer.host for peer, _ in healthy)),
        "abnormal_datastores": dict(Counter(ds for peer, _ in abnormal for ds in peer.datastores)),
        "healthy_datastores": dict(Counter(ds for peer, _ in healthy for ds in peer.datastores)),
        "abnormal_base_disks": dict(Counter(peer.base_disk for peer, _ in abnormal if peer.base_disk)),
        "healthy_base_disks": dict(Counter(peer.base_disk for peer, _ in healthy if peer.base_disk)),
        # What a device check flags on the healthy VMs too cannot be what stops this one.
        # The VM itself is left out: a booting VM counts as healthy, and must not be
        # compared with itself.
        "healthy_device_blocks": sorted(
            {text for peer, _ in healthy if peer.moref != vm.moref for text in peer.device_blocks}
        ),
        "vm_list": [
            {
                "name": peer.name,
                "moref": peer.moref,
                "state": verdict.state,
                "host": peer.host,
                "datastores": peer.datastores,
            }
            for peer, verdict in peers
        ][:50],
    }
    findings = []
    signals: list[dict[str, Any]] = []
    if len(abnormal) > 1:
        findings.append(f"{len(abnormal)} of {len(peers)} VMs in this environment are abnormal")
        for dimension, bad, good in (
            ("host", result["abnormal_hosts"], result["healthy_hosts"]),
            ("datastore", result["abnormal_datastores"], result["healthy_datastores"]),
            ("base_disk", result["abnormal_base_disks"], result["healthy_base_disks"]),
        ):
            only_bad = sorted(name for name in bad if name and name not in good)
            if only_bad and good:
                signals.append({"kind": "only_abnormal_on", "dimension": dimension, "values": only_bad})
                findings.append(
                    f"the abnormal VMs are on {dimension.replace('_', ' ')} {', '.join(only_bad)}; "
                    "the healthy ones are not"
                )
            elif len(bad) == 1 and next(iter(bad)) in good:
                shared = next(iter(bad))
                signals.append({"kind": "shared_with_healthy", "dimension": dimension, "values": [shared]})
                findings.append(
                    f"abnormal and healthy VMs share {dimension.replace('_', ' ')} {shared}, "
                    "which argues against it"
                )
    elif len(abnormal) == 1 and len(peers) > 1:
        lone = abnormal[0][0]
        if about_vm and lone.moref == vm.moref:
            signals.append({"kind": "alone", "dimension": None, "values": []})
            findings.append("this VM is the only abnormal one in its environment")
        else:
            # Someone else is the odd one out: say who, without an "alone" signal
            # about a VM that is not the one being diagnosed.
            findings.append(f"{lone.name} ({lone.moref}) is the only abnormal VM of {len(peers)} here")
    result["findings"] = findings
    result["signals"] = signals
    return result


def conclude(  # noqa: C901, PLR0912, PLR0913, PLR0915 - one ordered list of causes, kept together
    verdict: Verdict,
    *,
    vm: VmFacts,
    cpu: dict[str, Any],
    disk: dict[str, Any],
    environment: dict[str, Any],
    logs: dict[str, Any],
    serial: dict[str, Any],
    console: dict[str, Any],
    host_log: dict[str, Any],
    snapshots: dict[str, Any] | None = None,
    consolidation_needed: bool = False,
    host_hardware: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Weigh the evidence into causes, strongest first, with what argues against each."""
    causes: dict[str, dict[str, Any]] = {}

    def evidence(cause: str, *, weight: int, text: str, against: bool = False) -> None:
        entry = causes.setdefault(cause, {"cause": cause, "for": [], "against": [], "score": 0})
        entry["against" if against else "for"].append(text)
        entry["score"] += -weight if against else weight

    if verdict.state == INACCESSIBLE:
        evidence(INACCESSIBLE_CAUSE, weight=4, text=verdict.reasons[0])
    if verdict.state == BLOCKED_ON_QUESTION:
        evidence(QUESTION, weight=5, text=verdict.reasons[0])
    if BOOT_LOOP in verdict.flags:
        # Repeated resets are the finding whatever the last boot then did: each boot
        # that stops early is one turn of the loop, not a separate hang.
        evidence(
            BOOT_LOOP_CAUSE,
            weight=3,
            text=f"{verdict.values.get('resets_in_window')} resets or guest reboots in the boot-loop window",
        )
    shared_devices = set(environment.get("healthy_device_blocks", []))
    for finding in vm.device_blocks:
        # A hint: a disconnected NIC or a device error can matter (PXE, a stuck
        # device), but rarely stops a boot from completing, so it is weighed
        # below a CPU or storage cause rather than above it.
        if finding in shared_devices:
            # Not counted for: a healthy VM has it too. Said, so a reader need not check.
            evidence(
                HARDWARE,
                weight=0,
                against=True,
                text=f"a healthy VM in its environment has the same: {finding}",
            )
        else:
            evidence(HARDWARE, weight=1, text=finding)
    if snapshots and snapshots["count"]:
        gb = snapshots["total_bytes"] / (1024**3)
        if gb >= 1:
            evidence(SNAPSHOT, weight=1, text=f"{gb:.1f} GB in {snapshots['count']} snapshot(s)")
        if (snapshots.get("oldest_age_hours") or 0) >= 24:  # noqa: PLR2004
            days = snapshots["oldest_age_hours"] / 24
            evidence(SNAPSHOT, weight=1, text=f"oldest snapshot {days:.1f} days old")
        if snapshots.get("max_chain_depth", 0) >= 4:  # noqa: PLR2004
            evidence(
                SNAPSHOT, weight=1, text=f"redo chain {snapshots['max_chain_depth']} deep slows every read"
            )
    if consolidation_needed:
        evidence(
            SNAPSHOT,
            weight=2,
            text="consolidation needed: a snapshot delete left delta disks behind that keep growing",
        )
    if verdict.state == PAUSED:
        evidence(PAUSED_CAUSE, weight=5, text=verdict.reasons[0])
    values = verdict.values
    if MEMORY_RECLAIMED in verdict.flags:
        evidence(
            MEMORY,
            weight=2,
            text=(
                f"{values.get('ballooned_mb') or 0} MB ballooned, "
                f"{values.get('swapped_mb') or 0} MB swapped, "
                f"{values.get('compressed_kb') or 0} KB compressed"
            ),
        )
    if HOST_MEMORY_PRESSURE in verdict.flags:
        evidence(MEMORY, weight=2, text=f"its host is at {values.get('host_memory_percent')}% of memory")
    if HOST_NOT_CONNECTED in verdict.flags:
        evidence(HOST_DISCONNECTED, weight=3, text="vCenter reports the host not connected")
    hardware = host_hardware or {}
    red = hardware.get("red") or []
    if red:
        # A hot CPU or failing memory throttles or stalls every VM on the host while
        # its CPU numbers look normal; a lost redundant power supply or fan usually
        # does not, so it weighs less, under the counter-based causes.
        slows = [sensor for sensor in red if _slows_vms(sensor)]
        names = ", ".join(sorted({str(sensor.get("name")) for sensor in slows or red})[:5])
        evidence(HOST_HARDWARE, weight=2 if slows else 1, text=f"host hardware sensors red: {names}")
    if HEARTBEAT_INTERMITTENT in verdict.flags:
        evidence(TOOLS_FLAPPING_CAUSE, weight=2, text="Tools runs but its heartbeat is intermittent (yellow)")
    if CPU_LIMITED in verdict.flags and verdict.state not in (OFF, SUSPENDED):
        # Strongest when it is stuck; on a VM that is up but slow it is still the
        # first thing to rule out, since it looks exactly like host starvation.
        evidence(
            CPU_LIMIT_CAUSE,
            weight=3 if verdict.state in (BUSY_NOT_UP, HUNG, BOOTED_NOT_UP) else 2,
            text=f"a CPU limit of {values.get('cpu_limit_mhz')} MHz is set: the VM is capped below its "
            "full speed, which looks like host starvation but is configured, not the host",
        )
    if MEMORY_LIMITED in verdict.flags and MEMORY_RECLAIMED in verdict.flags:
        evidence(
            MEMORY_LIMIT_CAUSE,
            weight=2,
            text=f"a memory limit of {values.get('memory_limit_mb')} MB is set below the VM's "
            f"{values.get('memory_mb')} MB RAM, so the host must balloon or swap it",
        )
    elif MEMORY_LIMITED in verdict.flags:
        evidence(
            MEMORY_LIMIT_CAUSE,
            weight=1,
            text=f"a memory limit of {values.get('memory_limit_mb')} MB is set below the VM's "
            f"{values.get('memory_mb')} MB RAM: nothing is reclaimed yet, but the guest cannot use "
            "the RAM above the limit without the host ballooning or swapping it",
        )

    if cpu.get("available", True):
        for text in cpu.get("findings", []):
            evidence(CPU, weight=2, text=text)
        host = cpu.get("host") or {}
        ready = cpu.get("vm_ready_percent_per_vcpu")
        if ready and not cpu.get("starved"):
            evidence(
                CPU,
                weight=1,
                against=True,
                text=f"ready time peaked at only {ready['max']:.1f}% per vCPU",
            )
        if host.get("basis") == "demand" and host.get("overcommitted") is False:
            evidence(
                CPU,
                weight=1,
                against=True,
                text=f"host {host.get('name')} CPU {host.get('basis')} peaked at "
                f"{host['peak_percent_of_capacity']}% of capacity",
            )
    if disk.get("available", True):
        capacity_findings = disk.get("capacity_findings", [])
        for text in disk.get("findings", []):
            if text in capacity_findings:
                evidence(DATASTORE_CAPACITY, weight=3, text=text)
            else:
                evidence(STORAGE, weight=2, text=text)
        if not disk.get("slow") and any(
            entry.get("matched_instance") for entry in disk.get("datastores", [])
        ):
            evidence(
                STORAGE,
                weight=1,
                against=True,
                text="datastore latency stayed under the threshold in the window",
            )
    if host_log.get("available") and host_log.get("storage_lines_total"):
        evidence(
            STORAGE,
            weight=1,
            text=f"{host_log['storage_lines_total']} storage warnings in {host_log['host']}'s vmkernel log",
        )

    for signal in environment.get("signals", []):
        where = f"{(signal['dimension'] or '').replace('_', ' ')} {', '.join(signal['values'])}".strip()
        if signal["kind"] == "only_abnormal_on":
            text = f"in its environment, only the abnormal VMs are on {where}"
            if signal["dimension"] == "host":
                evidence(CPU, weight=1, text=text)
            else:
                evidence(STORAGE, weight=1, text=text)
            if signal["dimension"] == "base_disk":
                evidence(BOOT_STORM, weight=2, text=text)
        elif signal["kind"] == "shared_with_healthy":
            text = f"healthy VMs in its environment are on the same {where}"
            target = CPU if signal["dimension"] == "host" else STORAGE
            evidence(target, weight=1, against=True, text=text)

    for item in serial.get("files", []):
        for code in item.get("windows_stop_codes", []):
            label = f"{code['code']} {code['name'] or ''}".strip()
            evidence(WINDOWS_CRASH, weight=4, text=f"serial console: stop code {label}")
            hint = code.get("points_at") or ""
            if hint.startswith("storage"):
                evidence(STORAGE, weight=1, text=f"{label} usually means {hint}")
            if hint.startswith("CPU"):
                evidence(CPU, weight=1, text=f"{label} usually means {hint}")
        earlier = item.get("linux_findings_earlier_boots", [])
        if earlier:
            # A panic before the latest boot: often the very crash a kdump or capture
            # kernel (which prints its own banner) then booted after. Weighed once, lightly,
            # however many kinds it matched, so an old crash cannot outweigh today's cause.
            kinds = ", ".join(finding["kind"] for finding in earlier)
            evidence(KERNEL_ERROR, weight=1, text=f"serial console, an earlier boot: {kinds}")
        for finding in item.get("linux_findings", []):
            evidence(
                KERNEL_ERROR, weight=3, text=f"serial console: {finding['kind']}: {finding['examples'][0]}"
            )
            hint = finding.get("points_at") or ""
            if hint.startswith("storage"):
                evidence(STORAGE, weight=1, text=f"{finding['kind']}: {hint}")
            if hint.startswith("CPU"):
                evidence(CPU, weight=1, text=f"{finding['kind']}: {hint}")

    if console.get("available"):
        for state in console.get("screen_states", []):
            name = state["state"]
            if name == "blue_screen":
                evidence(WINDOWS_CRASH, weight=4, text=f"console: {state['meaning']}")
            elif name in ("windows_updating", "device_setup", "disk_check", "windows_starting"):
                evidence(STILL_WORKING, weight=3, text=f"console: {state['meaning']}")
            elif name in (
                "automatic_repair",
                "boot_manager_error",
                "no_boot_device",
                "linux_emergency",
                "linux_panic",
            ):
                evidence(CANNOT_BOOT, weight=4, text=f"console: {state['meaning']}")
            elif name in ("windows_logon", "linux_login"):
                evidence(TOOLS_DID_NOT_START, weight=4, text=f"console: {state['meaning']}")
        read_words = bool(console.get("screen_states") or console.get("stop_codes"))
        # Without the words, a still screen's colour is a hint only for a Windows VM
        # that did not come up: an idle VM at a blue sign-in screen, or a Server Core
        # console, is still too, and VGA-blue Linux installer screens score as blue.
        guess_from_colour = (
            console.get("frozen")
            and not read_words
            and vm.os_family == "windows"
            and vm.tools_running != "guestToolsRunning"
        )
        if guess_from_colour and console.get("blue_screen_colour"):
            evidence(
                WINDOWS_CRASH,
                weight=2,
                text="console mostly Windows blue and unchanged, Tools not running (no OCR to confirm; "
                "the recovery screens use the same blue)",
            )
        if guess_from_colour and console.get("text_on_black"):
            # Windows has no text console to log in at: still text on black is the
            # black stop-error screen of 24H2+, or a firmware/boot-manager error.
            for cause in (WINDOWS_CRASH, CANNOT_BOOT):
                evidence(
                    cause,
                    weight=1,
                    text="console shows still text on black on a Windows guest, Tools not running: a "
                    "stop error (the 24H2+ black screen) or a boot error (no OCR to tell which)",
                )
        if console.get("frozen") and console.get("text_on_black"):
            # Mostly black but not blank: something printed, so this is no early hang.
            # On Linux it is a text console or login prompt; Windows has none.
            if vm.os_family != "windows":
                evidence(
                    TOOLS_DID_NOT_START,
                    weight=1,
                    text="console shows text on a dark screen (a text console or login prompt), unchanged",
                )
        elif console.get("frozen") and console.get("black"):
            evidence(EARLY_HANG, weight=2, text="console black and unchanged across captures")
        elif console.get("frozen"):
            # A boot screen that does not move is not a boot that is progressing; but
            # an update or disk-check screen can sit still for seconds while it works,
            # so on those the stillness weighs less and is no evidence of a hang.
            shown = {state["state"] for state in console.get("screen_states", [])}
            slow_progress = bool(shown & {"windows_updating", "device_setup", "disk_check"})
            evidence(
                STILL_WORKING,
                weight=1 if slow_progress else 2,
                against=True,
                text="the console did not change across captures",
            )
            if not slow_progress:
                evidence(EARLY_HANG, weight=1, text="the console screen is unchanged across captures")
        if console.get("frozen") is False:
            evidence(EARLY_HANG, weight=2, against=True, text="the console changed between captures")
            evidence(STILL_WORKING, weight=1, text="the console changed between captures")
        for code in console.get("stop_codes", []):
            evidence(WINDOWS_CRASH, weight=3, text=f"console: stop code {code['code']} {code['name'] or ''}")

    timeline = logs.get("timeline") or {}
    if timeline.get("boot_found"):
        last = timeline.get("last_stage")
        if last in ("power_on_or_reset", "firmware", "guest_disk_io"):
            evidence(
                EARLY_HANG,
                weight=1,
                text=f"vmware.log: the boot got as far as {last}, then nothing further was logged",
            )
        elif last in ("guest_drivers", "tools"):
            evidence(EARLY_HANG, weight=1, against=True, text=f"vmware.log: the boot reached {last}")
        if timeline.get("annotations", {}).get("fault"):
            evidence(VM_FAULT, weight=3, text="vmware.log reports a fault during boot")
        if timeline.get("annotations", {}).get("storage"):
            evidence(STORAGE, weight=1, text="vmware.log reports storage trouble during boot")
    if logs.get("tools_state_changes", 0) >= 3:  # noqa: PLR2004
        evidence(
            TOOLS_FLAPPING_CAUSE,
            weight=2,
            text=f"{logs['tools_state_changes']} Tools state changes in vmware.log",
        )
        verdict.flags.append(TOOLS_FLAPPING)

    if verdict.state == HUNG:
        evidence(EARLY_HANG, weight=1, text=verdict.reasons[-1])
        evidence(CPU, weight=1, against=True, text="the VM uses almost no CPU")
        evidence(STILL_WORKING, weight=1, against=True, text="the VM uses almost no CPU")
    if verdict.state == BUSY_NOT_UP:
        evidence(STILL_WORKING, weight=1, text=verdict.reasons[-1])

    if BOOT_LOOP_CAUSE in causes and EARLY_HANG in causes:
        # Each boot of a loop stops early, then resets: what reads as an early hang
        # (a black console, a log that stops at firmware) is one turn of the loop.
        hang = causes.pop(EARLY_HANG)
        loop = causes[BOOT_LOOP_CAUSE]
        loop["for"].extend(f"each boot stops early: {text}" for text in hang["for"])
        loop["score"] += max(hang["score"], 0)
    ranked = sorted(causes.values(), key=lambda entry: entry["score"], reverse=True)
    for entry in ranked:
        support, opposed = len(entry["for"]), len(entry["against"])
        entry["confidence"] = (
            "high"
            if entry["score"] >= 4 and not opposed  # noqa: PLR2004
            else "medium"
            if entry["score"] >= 2  # noqa: PLR2004
            else "low"
        )
        entry["evidence_count"] = support + opposed
    likely = [entry for entry in ranked if entry["score"] > 0]
    starved_not_hung = verdict.state == BUSY_NOT_UP and cpu.get("starved")
    not_checked = [
        name
        for name, part in (
            ("CPU counters", cpu),
            ("storage counters", disk),
            ("vmware.log", logs),
            ("serial console", serial),
            ("console screen", console),
            ("host vmkernel log", host_log),
        )
        if not part.get("available", True)
    ]
    # Read, but empty: a window vCenter no longer keeps at this resolution.
    not_checked.extend(
        f"{name} (no samples for the window: rolled up, or below the statistics level)"
        for name, part in (("CPU counters", cpu), ("storage counters", disk))
        if part.get("available", True) and part.get("window_read") is False
    )
    headline = (
        f"likely cause: {likely[0]['cause']} ({likely[0]['confidence']} confidence)"
        if likely
        else "no cause stands out from the evidence read"
    )
    if starved_not_hung:
        headline += "; the VM is busy, so it is more likely booting slowly than hung"
    if verdict.state == HEALTHY:
        headline += (
            "; vCenter sees the VM up (Tools running), so these are what would slow it, not why it is stuck"
        )
    if verdict.state == NO_TOOLS:
        headline += (
            "; VMware Tools is not installed, so its absence says nothing: judge by the console, "
            "CPU and boot log"
        )
    return {
        "headline": headline,
        "causes": likely,
        "argued_against": [entry for entry in ranked if entry["score"] <= 0],
        "not_checked": not_checked,
        "vm_state": verdict.state,
        "flags": verdict.flags,
        "alarms": verdict.values.get("alarms", []),
    }


def next_checks(conclusion: dict[str, Any], vm: VmFacts) -> list[str]:
    """The checks that would separate the leading causes."""
    leading = {entry["cause"] for entry in conclusion["causes"][:2]}
    steps = []
    if CPU in leading:
        steps.append(f"explain_group on host {vm.host!r} from a scan: are other VMs on it starved too?")
        steps.append("vROps: the host's or cluster's CPU demand over the past days at this hour")
    if MEMORY in leading:
        steps.append(f"get_host_health on {vm.host!r}: is the host itself out of memory?")
    if DATASTORE_CAPACITY in leading:
        steps.append(
            "check_datastores: the datastore's fill, thin over-provisioning and per-host reachability"
        )
    if leading & {STORAGE, BOOT_STORM}:
        steps.append("get_datastore_health on the VM's datastores over a wider window")
        steps.append("powerflex_health (if configured): is a rebuild/rebalance running on the backend?")
    if leading & {EARLY_HANG, CANNOT_BOOT, VM_FAULT}:
        steps.append("does the same base disk boot fine on another host or datastore right now?")
    if BOOT_LOOP_CAUSE in leading:
        steps.append(
            "who resets it: vCenter events name the user or HA, vmware.log says 'Guest-initiated reset' "
            "for the guest's own; the serial console or console after a reset shows why"
        )
    if leading & {WINDOWS_CRASH, KERNEL_ERROR}:
        steps.append("the stop code or kernel message: does it point at storage or CPU (points_at)?")
    if STILL_WORKING in leading:
        steps.append("take the console again in a few minutes: is it still progressing?")
    if not leading:
        steps.append("scan the vCenter: is this VM alone, or part of a group?")
    steps.append(
        "your orchestrator's / monitoring's logs: when the reboot was asked for, and how long it "
        "waited for Tools before raising the error"
    )
    return steps


# -- the composites --------------------------------------------------------------


def _env_reboots(
    session: VCenterSession,
    now: datetime,
    folder_moref: str | None,
    peers: list[VmFacts],
    lookback_hours: float,
    window_minutes: float,
) -> tuple[dict[str, datetime], dict[str, int], str | None]:
    """The latest reboot event per VM of an environment, its resets in the boot-loop window, and a note.

    One query scoped to the environment's folder (not the whole vCenter, whose
    events would crowd out the folder's past the QueryEvents cap), so a mass
    warm reboot does not make every peer look long-stuck and a peer in a boot
    loop is not counted as healthy. The note says when that could not be read
    in full.
    """
    if not peers:
        return {}, {}, None
    entity = session.reference("Folder", folder_moref) if folder_moref else None
    try:
        events = session.events(
            entity=entity,
            recursion="all",
            begin=now - timedelta(hours=lookback_hours),
            end=now,
            types=RESET_EVENTS,
        )
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and retry
    except (VSphereError, vmodl.MethodFault) as error:
        return {}, {}, f"reboot events not read ({type(error).__name__}); uptime is from power-on"
    note = None
    if len(events) >= QUERY_EVENTS_CAP:
        note = (
            f"{len(events)} reset events in the environment's window: vCenter returns at most "
            f"{QUERY_EVENTS_CAP}, so some reboots and boot-loop counts may be missed"
        )
    return latest_reboot_by_vm(events), resets_by_vm(events, window_minutes, now), note


def _gaps_for(settings: Settings, vm: VmFacts, *, storage_implicated: bool) -> list[dict[str, Any]]:
    """The evidence gaps for a VM: the always-relevant ones, plus PowerFlex when storage is in play."""
    gaps = capabilities.evidence_gaps(settings, vm)
    if storage_implicated and (powerflex_gap := capabilities.powerflex_gap(settings)):
        gaps.append(powerflex_gap)
    return gaps


def diagnose_vm(
    session: VCenterSession,
    settings: Settings,
    *,
    env_id: str | None,
    vm_name: str | None,
    moref: str | None,
    rebooted_at: datetime | None = None,
    console_captures: int = 2,
    console_interval_seconds: float = 10.0,
) -> dict[str, Any]:
    """Everything about one VM, in the fixed order, ending in the likely cause."""
    located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref)
    if not located["found"]:
        return {"found": False} | {key: value for key, value in located.items() if key != "found"}
    vm: VmFacts = located["vm"]
    row = located["row"]
    layout: Layout = located["layout"]
    thresholds = settings.thresholds
    now = session.now()
    host = layout.hosts.get(vm.host_moref or "")
    snapshots = snapshot_usage(row.get("snapshot"), row.get("layoutEx"), now)

    # Find the reboot before judging uptime: a warm reboot does not move
    # runtime.bootTime, so without this the VM looks up for days. Look back over
    # the VM's life (capped), not from bootTime, since bootTime may be the stale
    # power-on. The caller's rebooted_at (from an orchestrator/monitoring) wins when given.
    lookback = min(max(vm.age_hours or 24.0, 1.0), 24.0)
    events = piece(
        "events",
        lambda: {
            "events": session.events(
                entity=session.reference("VirtualMachine", vm.moref),
                begin=now - timedelta(hours=lookback),
                end=now,
            )
        },
    )
    raw_events = events.get("events", [])
    reboots = latest_reboot_by_vm(raw_events)
    # The log first: a reboot started in the guest is only in vmware.log, and the
    # verdict (booting or stuck) rests on when this boot began.
    logs = piece("vmware.log", lambda: read_logs(session, settings, vm, row))
    log_boot = (logs.get("timeline") or {}).get("boot_started") if logs.get("available") else None
    set_effective_boot(vm, now, reboots=reboots, rebooted_at=rebooted_at, log_boot=log_boot)
    begin, end = window(now, vm.boot_time)
    resets = resets_by_vm(raw_events, thresholds.boot_loop_window_minutes, now).get(vm.moref, 0)
    verdict = classify(vm, thresholds, resets_in_window=resets)

    peers: list[tuple[VmFacts, Verdict]] = []
    if vm.folder_moref:
        siblings = read_vms(session, layout, root=session.reference("Folder", vm.folder_moref))
        # The peers were read without reboot events; a mass reboot would make
        # them all look long-stuck. Refine each from its own reset/reboot event.
        peer_reboots, peer_resets, peer_note = _env_reboots(
            session,
            now,
            vm.folder_moref,
            [peer for peer, _ in siblings],
            lookback,
            thresholds.boot_loop_window_minutes,
        )
        if peer_note:
            vm.notes.append(f"environment: {peer_note}")
        peers = []
        for peer, _ in siblings:
            if peer.folder_moref != vm.folder_moref:
                continue
            if peer.moref == vm.moref:
                # The VM itself, already judged with its own events and rebooted_at.
                peers.append((vm, verdict))
                continue
            set_effective_boot(peer, now, reboots=peer_reboots)
            resets_seen = peer_resets.get(peer.moref, 0)
            peers.append((peer, classify(peer, thresholds, resets_in_window=resets_seen)))
    environment = environment_pattern(vm, peers) if peers else {"vms": 0, "findings": []}
    cpu = piece("CPU", lambda: vm_cpu(session, vm, host, begin=begin, end=end, thresholds=thresholds))
    stores = [layout.datastores[m] for m in vm.datastore_morefs if m in layout.datastores]
    disk = piece(
        "storage",
        lambda: storage(
            session,
            {host.moref: host.name} if host else {},
            stores,
            begin=begin,
            end=end,
            thresholds=thresholds,
            vm_moref=vm.moref,
        ),
    )
    host_log = (
        piece("host log", lambda: read_host_storage_log(session, host))
        if host
        else {"available": False, "reason": "the VM's host is not known"}
    )
    host_hardware = (
        piece(
            "host hardware",
            lambda: classify_sensors(read_sensors(session, [host.moref]).get(host.moref, [])),
        )
        if host
        else {"available": False, "reason": "the VM's host is not known"}
    )
    serial = piece("serial console", lambda: read_serial_files(session, vm))
    console = (
        piece(
            "console",
            lambda: read_console(
                session, settings, vm, captures=console_captures, interval_seconds=console_interval_seconds
            ),
        )
        if console_captures > 0
        else {"available": False, "reason": "not asked for"}
    )

    conclusion = conclude(
        verdict,
        vm=vm,
        cpu=cpu,
        disk=disk,
        environment=environment,
        logs=logs,
        serial=serial,
        console=console,
        host_log=host_log,
        snapshots=snapshots,
        consolidation_needed=vm.consolidation_needed,
        host_hardware=host_hardware,
    )
    return {
        "found": True,
        "finding": conclusion["headline"],
        "conclusion": conclusion,
        "next_checks": next_checks(conclusion, vm),
        "vm": vm.identity() | {"notes": vm.notes, "read_at": now},
        "machine": verdict.as_dict()
        | {
            "question": vm.question.__dict__ if vm.question else None,
            "boot_time": vm.boot_time,
            "boot_time_source": vm.boot_source,
            "power_on_time": vm.power_on_time,
            "tools_version_status": vm.tools_version_status,
            "guest_state": vm.guest_state,
            "ip_address": vm.ip_address,
            "num_cpu": vm.num_cpu,
            "disk_chain": vm.disk_chain,
            "devices": vm.devices,
            "device_findings": vm.device_findings,
        },
        "window": {"from": begin, "to": end},
        "cpu": cpu,
        "storage": disk,
        "environment": environment,
        "boot": logs,
        "serial_console": serial,
        "console": console,
        "host_log": host_log,
        "host_hardware": host_hardware,
        "snapshots": snapshots or {"count": 0},
        "events": summarize_events(raw_events) if "events" in events else events,
        # Stronger sources this diagnosis lacked: name them so a reader does not
        # mistake "could not see it" for "it did not happen", and knows what to
        # turn on. Empty when nothing better was missing. The PowerFlex backend is
        # named only when storage is actually implicated, so it does not nag on a
        # VM whose trouble has nothing to do with the datastore.
        # Latency, or a datastore full or unreachable (APD/PDL): either way the backend
        # behind it is in question.
        "evidence_gaps": _gaps_for(
            settings, vm, storage_implicated=bool(disk.get("slow") or disk.get("capacity_findings"))
        ),
    }


def diagnose_environment(session: VCenterSession, settings: Settings, *, env_id: str) -> dict[str, Any]:
    """Every VM of an environment judged, grouped, and checked for CPU and storage."""
    layout = Layout.of(session)
    folders = find_environment(layout.folders, env_id, settings.env_parent_hints)
    if not folders:
        return {
            "found": False,
            "reason": f"no folder on {session.vcenter.name} is named {env_id!r} or contains it",
        }
    exact = [folder for folder in folders if folder.name.lower() == env_id.strip().lower()]
    if not exact and len(folders) == 1:
        exact = folders  # one folder contains the id: unambiguous, as locate() accepts it
    if len(exact) != 1:
        return {
            "found": False,
            "reason": f"{len(exact) or len(folders)} folders match {env_id!r}; none is unambiguous",
            "candidates": [{"path": folder.path, "parent": folder.parent_name} for folder in folders[:20]],
        }
    folder = exact[0]
    thresholds = settings.thresholds
    vms = [vm for vm, _ in read_vms(session, layout, root=session.reference("Folder", folder.moref))]
    now = session.now()
    # As in diagnose_vm: a warm reboot does not move bootTime, so measure each VM
    # from its latest reset or guest-reboot event, and count its boot-loop resets.
    lookback = min(max(max((vm.age_hours or 0.0) for vm in vms) if vms else 24.0, 1.0), 24.0)
    reboots, resets, reboot_note = _env_reboots(
        session, now, folder.moref, vms, lookback, thresholds.boot_loop_window_minutes
    )
    for vm in vms:
        set_effective_boot(vm, now, reboots=reboots)
    verdicts = [(vm, classify(vm, thresholds, resets_in_window=resets.get(vm.moref, 0))) for vm in vms]
    if not vms:
        return {
            "found": True,
            "folder": folder.path,
            "vms": 0,
            "finding": "the environment folder holds no VMs",
        }
    boots = [vm.boot_time for vm in vms if vm.boot_time]
    begin, end = window(now, min(boots) if boots else None)
    env_hosts = [
        layout.hosts[moref]
        for moref in {vm.host_moref for vm in vms if vm.host_moref}
        if moref in layout.hosts
    ]
    cpu = piece(
        "CPU",
        lambda: dict(
            zip(
                ("hosts", "counters_unavailable"),
                hosts_cpu(session, env_hosts, begin=begin, end=end, thresholds=thresholds),
                strict=True,
            )
        ),
    )
    morefs = {moref for vm in vms for moref in vm.datastore_morefs}
    stores = [layout.datastores[m] for m in morefs if m in layout.datastores]
    disk = piece(
        "storage",
        lambda: storage(
            session,
            {host.moref: host.name for host in env_hosts},
            stores,
            begin=begin,
            end=end,
            thresholds=thresholds,
        ),
    )
    pattern = environment_pattern(vms[0], verdicts, about_vm=False)
    findings = list(pattern["findings"])
    over = [host for host in (cpu.get("hosts") or {}).values() if host.get("overcommitted")]
    findings.extend(
        f"host {host['name']} CPU demand peaked at {host['peak_percent_of_capacity']}% of capacity"
        for host in over
    )
    findings.extend(disk.get("findings", []))
    abnormal = [(vm, verdict) for vm, verdict in verdicts if verdict.abnormal]
    if not findings:
        findings.append(
            "no abnormal VMs"
            if not abnormal
            else "abnormal VMs, but no shared host or storage cause stands out"
        )
    return {
        "found": True,
        "folder": folder.path,
        "folder_parent": folder.parent_name,
        "finding": findings[0],
        "findings": findings,
        "counts_by_state": pattern["counts_by_state"],
        "vms": [vm.identity() | {"verdict": verdict.as_dict()} for vm, verdict in verdicts],
        "window": {"from": begin, "to": end},
        "hosts_cpu": cpu,
        "storage": disk,
        "pattern": pattern,
        "notes": [reboot_note] if reboot_note else [],
        "next": "diagnose_vm on one abnormal VM for its console, vmware.log and serial console",
    }
