"""Tool surface: vCenters and vROps, read-only, shaped for diagnosing VMs that did not come back.

Each tool answers a question a person asks during an incident ("what is wrong
on these vCenters", "why is this machine stuck") rather than mirroring one API
call. Results lead with findings and keep the numbers they were judged on;
they are bounded because they land in a context window.

Every tool is read-only, and says so in its MCP annotations. The guarantee
itself is `readonly.ReadOnlyStub`, not the annotation.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import io
import logging
import re
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import TYPE_CHECKING, Any

import httpx
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from PIL import Image
from pyVmomi import vim, vmodl
from starlette.responses import JSONResponse

from vsphere_triage import ages, guestexec, hardware, resources, snapshots, storagehealth, timecheck
from vsphere_triage import scan as scanning
from vsphere_triage.checks import classify, count_states
from vsphere_triage.config import Settings
from vsphere_triage.contention import hosts_cpu, storage
from vsphere_triage.diagnose import (
    Layout,
    diagnose_environment,
    diagnose_vm,
    locate,
    read_console,
    read_logs,
    read_serial_files,
    read_vms,
    summarize_events,
    vm_folder,
)
from vsphere_triage.formatting import bounded
from vsphere_triage.inventory import find_environment as environment_folders
from vsphere_triage.readonly import ReadOnlyViolationError
from vsphere_triage.vcenter import VCenterPool, VSphereError
from vsphere_triage.vmlog import grep, parse_lines
from vsphere_triage.vrops import KINDS, SUGGESTED_STAT_KEYS, Vrops, VropsError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from starlette.requests import Request

    from vsphere_triage.vcenter import VCenterSession

# Failures a caller can act on: a bad argument, an unreachable or slow vCenter,
# a vROps refusal, a refused write. Their message reaches the model.
ANTICIPATED = (
    ValueError,
    re.error,
    VSphereError,
    VropsError,
    ReadOnlyViolationError,
    vmodl.MethodFault,
    httpx.HTTPError,
    http.client.HTTPException,
    OSError,
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
# run_in_guest is the one tool that acts on a VM; it is not read-only and says so.
GUEST_EXEC = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
MAX_LIMIT = 500

INSTRUCTIONS = """\
Read-only access to the vCenters (and vROps, if configured), for diagnosing VMs
that are stuck — on first boot, after a reboot, or hung at any point — slow to
come up, losing VMware Tools, blocked on a question, starved, or wedged by a
virtual device; and for when the vCenter API itself is the problem (SSL EOF
errors, resets, timeouts, often connection or session exhaustion). Every tool
reads only, with one deliberate exception: run_in_guest executes a command
inside a guest OS (it needs VMware Tools running and guest credentials) for a
diagnostic a read cannot answer. It is marked not-read-only; nothing else can
change a VM.

When the symptom is SSL EOF / reset / timeout against a vCenter that many
clients hit (this server included), start with check_vcenters: a high session
count or slow login points at the vCenter near its limit, not at any one VM.

Concepts:
- Environments are short-lived (minutes to a day) and each is a folder named by
  its environment id, under a parent folder that groups environments (some
  vCenters call it environments, others projects). The layout is discovered,
  not assumed: find_environment reports where it found a folder.
- A VM is identified by its vCenter and moref. Its name is reused by later
  environments, so a name means something only inside its environment folder.
  Carry {vcenter, moref} from the first result to the last.
- Most VMs are linked clones of a shared base disk; many clones booting at once
  read one disk on one datastore.

Two ways in:
1. From a VMware Tools error your monitoring raised, which names the vCenter,
   the machine and the environment id: diagnose_vm(vcenter, env_id=..., vm_name=...).
2. From a question about the fleet ("anything stuck on vc-04?"): scan, then
   explain_group on its strongest group, then diagnose_vm on that group's
   representatives. A past window, when VMs are gone: diagnose_window.

Reading the answers:
- Shared causes first. CPU starvation on an overcommitted ESXi host (ready time,
  host demand over 100% of capacity) and storage latency (a saturated datastore
  or its backing array) have both stopped VMs from coming back. Check the host
  and the storage before explaining the guest, and check that the healthy VMs
  beside the stuck ones were not in the same situation before blaming what they
  share.
- Starved is not hung: a VM busy on CPU with a changing console is booting
  slowly and may come up; the Tools error is then a timeout upstream.
- vmware.log is the hypervisor's log, not the guest's: it shows how far a boot
  got (firmware, disk, drivers, Tools), never the kernel's own message. The
  serial console (Windows EMS, a Linux kernel console) and the console screen
  carry the guest's words when present; their absence is normal.
- Every result says what it could not read. Missing data is not evidence that
  nothing happened.
"""


def _names(pool: VCenterPool, vcenters: list[str] | None) -> list[str]:
    if not vcenters:
        return pool.names()
    return [pool.resolve(name) for name in vcenters]


def _parse_time(text: str) -> datetime:
    value = datetime.fromisoformat(text.strip())
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _since(text: str | None, default: datetime) -> datetime:
    return _parse_time(text) if text else default


def build_server(settings: Settings | None = None, pool: VCenterPool | None = None) -> MCPServer:
    """Wire every tool onto a server bound to the configured vCenters."""
    resolved = settings or (pool.settings if pool else Settings.from_environment())
    # Every datastore read would otherwise log a line, into a stdio client's log pane.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    fleet = pool or VCenterPool(resolved)
    scans = scanning.ScanStore(resolved.max_scans_kept)
    vrops = Vrops(resolved) if resolved.vrops_url else None

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncGenerator[dict[str, Any]]:
        try:
            yield {}
        finally:
            fleet.close()
            if vrops is not None:
                await vrops.aclose()

    server = MCPServer(
        name="vsphere-triage",
        title="vSphere triage (read-only)",
        version="0.1.0",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )

    tool = _registrar(server, resolved)

    @server.custom_route("/healthz", methods=["GET", "HEAD"])
    async def health(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    _register_fleet_tools(tool, fleet, resolved, scans, has_vrops=vrops is not None)
    _register_machine_tools(tool, fleet, resolved)
    _register_piece_tools(tool, fleet, resolved)
    _register_infrastructure_tools(tool, fleet, resolved)
    if vrops is not None:
        _register_vrops_tools(tool, vrops)
    server.vcenters = fleet  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute] - attached for the tests to read methods_seen
    return server


def _registrar(server: MCPServer, resolved: Settings) -> Callable[[str | None], Any]:
    """The decorator every tool is registered with: read-only, admitted, bounded, worded."""
    active = {"count": 0}

    def tool(
        name: str | None = None, *, annotations: ToolAnnotations = READ_ONLY
    ) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Any]:
        """Register a tool: admitted, bounded, a lookup miss answered rather than raised.

        Read-only by default; `annotations=GUEST_EXEC` marks the one tool that acts
        on a VM, so a client sees it is not read-only.
        """

        def register(function: Callable[..., Awaitable[dict[str, Any]]]) -> Any:
            @wraps(function)
            async def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
                if active["count"] >= resolved.max_concurrent_tools:
                    msg = "VSPHERE_MAX_CONCURRENT_TOOLS reached; retry when a call finishes"
                    raise ToolError(msg)
                active["count"] += 1
                try:
                    return bounded(await function(*args, **kwargs))
                except LookupError as error:
                    return bounded({"found": False, "reason": str(error).strip("'\"")})
                except ANTICIPATED as error:
                    # Said to the model in words; anything else is a crash the SDK hides.
                    raise ToolError(str(error)) from error
                finally:
                    active["count"] -= 1

            return server.tool(name=name or function.__name__, annotations=annotations)(wrapped)  # ty: ignore[unresolved-attribute] - the wrapped callable has __name__ at runtime

        return register

    return tool


def _register_fleet_tools(  # noqa: C901, PLR0915 - one closure per tool
    tool: Callable[..., Any],
    fleet: VCenterPool,
    resolved: Settings,
    scans: scanning.ScanStore,
    *,
    has_vrops: bool,
) -> None:
    """The fleet: which vCenters, what is abnormal on them, why, and over a past window."""
    # -- the fleet -------------------------------------------------------------

    @tool()
    async def list_vcenters() -> dict[str, Any]:
        """The configured vCenters: reachable or not, product, version and clock."""
        names = fleet.names()
        results = await asyncio.gather(
            *(fleet.run(name, lambda session: session.about()) for name in names),
            return_exceptions=True,
        )
        rows = []
        for name, result in zip(names, results, strict=True):
            if isinstance(result, BaseException):
                rows.append({"name": name, "reachable": False, "error": str(result)})
            else:
                rows.append({"reachable": True, **result})
        return {"vcenters": rows, "vrops_configured": has_vrops}

    @tool()
    async def check_vcenters(*, vcenters: list[str] | None = None) -> dict[str, Any]:
        """Each vCenter's reachability, login time, and open-session count.

        For when the symptom is the vCenter API itself — SSL EOF errors, resets
        or timeouts that many clients hit at once (this server included). A high
        or climbing session count, or a slow login, points at connection/session exhaustion
        on the vCenter, which looks like a dropped connection to every client.
        The session count needs the account to be allowed the global session
        list; otherwise only this server's own session is visible and it says so.

        Args:
            vcenters: vCenter names; all when empty.

        """
        names = _names(fleet, vcenters)

        def probe(session: VCenterSession) -> dict[str, Any]:
            started = time.monotonic()
            about = session.about()
            login_seconds = round(time.monotonic() - started, 2)
            return {
                "reachable": True,
                **about,
                "login_seconds": login_seconds,
                "sessions": session.session_count(),
            }

        results = await asyncio.gather(*(fleet.run(name, probe) for name in names), return_exceptions=True)
        rows, findings = [], []
        for name, result in zip(names, results, strict=True):
            if isinstance(result, BaseException):
                rows.append({"name": name, "reachable": False, "error": str(result)})
                findings.append(f"{name}: not reachable — {result}")
                continue
            rows.append(result)
            sessions = result.get("sessions", {})
            if sessions.get("total") is not None:
                findings.append(
                    f"{result['name']}: {sessions['total']} open sessions, login {result['login_seconds']}s"
                )
        return {"vcenters": rows, "findings": findings or ["all configured vCenters reachable"]}

    @tool()
    async def vcenter_sessions(*, vcenter: str) -> dict[str, Any]:
        """Who is holding a vCenter's open sessions — for diagnosing exhaustion.

        When a vCenter is refusing connections (SSL EOF, resets), this reads its
        open API sessions and groups them by user, source IP and client, with
        how many are idle past the timeout and the oldest ones. A single client
        holding most of the sessions, or many idle sessions from one source, is
        the usual cause: a client that opens sessions and never closes them.
        Needs the account to be allowed the global session list; otherwise only
        this server's own session is visible and the result says so (then read
        the vCenter's session count from vROps instead).

        Args:
            vcenter: the vCenter to read.

        """
        name = fleet.resolve(vcenter)
        sessions = await fleet.run(name, lambda session: session.sessions())
        return {"vcenter": name, **sessions}

    @tool()
    async def scan(
        *,
        vcenters: list[str] | None = None,
        states: list[str] | None = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        """Find abnormal VMs on some or all vCenters, and what the abnormal ones share.

        Judges every VM (stuck after boot, hung, busy but not up, blocked on a
        question, lost heartbeat, inaccessible, boot loops) and groups the
        abnormal ones by vCenter, cluster, host, datastore, environment folder,
        linked-clone base disk and OS, each against its population. Also reports
        hosts over the CPU threshold and slow storage right now.

        Args:
            vcenters: vCenter names (any spelling they are known by); all when empty.
            states: only these states or flags, e.g. ["no_tools"] or ["long_running"]; the
                abnormal states and attention flags when empty.
            limit: how many abnormal VMs to list (groups and counts always cover all).

        """
        names = _names(fleet, vcenters)
        wanted = tuple(states) if states else scanning.FLAGGED
        unknown = [state for state in wanted if state not in scanning.SELECTABLE]
        if unknown:
            msg = f"unknown states or flags {unknown}; choose from {list(scanning.SELECTABLE)}"
            raise ValueError(msg)
        result = await scanning.run_scan(fleet, resolved, names)
        scans.put(result)
        return scanning.summary(result, states=wanted, limit=max(1, min(limit, MAX_LIMIT)))

    @tool()
    async def explain_group(*, scan_id: str, dimension: str, value: str) -> dict[str, Any]:
        """Why a group from a scan is abnormal: what its VMs share that healthy VMs do not.

        Compares the group's abnormal VMs with the healthy VMs in the same group
        on every other dimension, then checks host CPU demand and storage latency
        over the group's boot window.

        Args:
            scan_id: from scan.
            dimension: vcenter, cluster, host, datastore, environment_folder, folder_parent,
                base_disk or os_family.
            value: the group's value, as scan printed it.

        """
        return await scanning.explain_group(fleet, resolved, scans.get(scan_id), dimension, value)

    @tool()
    async def find_old_environments(
        *,
        older_than_hours: float = 5.0,
        vcenters: list[str] | None = None,
        under: list[str] | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Environments (and their VMs) that have existed longer than a number of hours.

        An environment is the folder its VMs sit in; its age is its oldest VM's
        creation time. Use `under` to keep only folders below a path segment
        ("projects", "environments") or a run of them ("projects/team-a"), at
        any depth. Oldest first, with each environment's VM states, so a
        leftover that is still powered on stands out.

        Args:
            older_than_hours: minimum age, in hours.
            vcenters: vCenter names; all when empty.
            under: folder path segments to look under; everywhere when empty.
            limit: how many environments to list (the count covers all).

        """
        names = _names(fleet, vcenters)
        return await ages.find_old_environments(
            fleet,
            resolved,
            names,
            older_than_hours=max(0.0, older_than_hours),
            under=[term for term in (under or []) if term.strip("/ ")],
            limit=max(1, min(limit, MAX_LIMIT)),
        )

    @tool()
    async def find_vms_by_device(
        *,
        device: str,
        present: bool = True,
        vcenters: list[str] | None = None,
        under: list[str] | None = None,
        include_templates: bool = True,
        limit: int = 200,
    ) -> dict[str, Any]:
        """VMs across the vCenters that have, or lack, a given virtual device.

        For a production issue that turns on a device: find every VM with (or
        without) a sound card, a VMXNET3 adapter, a USB controller, a mounted
        CD-ROM, and so on. `device` is a category — ethernet, disk, cdrom,
        serial, sound, usb, controller, video, input — or a kind substring such
        as "Vmxnet3" or "HdAudioCard". This reads each VM's device list, the one
        heavy property, so scope it with `vcenters`/`under` on a large fleet.

        Args:
            device: a device category or a kind substring to match.
            present: True for VMs that have it, False for VMs that lack it.
            vcenters: vCenter names; all when empty.
            under: folder path segments to look under; everywhere when empty.
            include_templates: also consider template VMs (a bare template is
                usually why its clones lack a device).
            limit: how many matching VMs to list (the count covers all).

        """
        names = _names(fleet, vcenters)
        return await hardware.find_vms_by_device(
            fleet,
            resolved,
            names,
            device=device,
            present=present,
            include_templates=include_templates,
            under=[term for term in (under or []) if term.strip("/ ")],
            limit=max(1, min(limit, MAX_LIMIT)),
        )

    @tool()
    async def find_vms_by_snapshot(
        *,
        min_total_gb: float = 0.0,
        older_than_hours: float | None = None,
        min_count: int = 1,
        only_problems: bool = False,
        vcenters: list[str] | None = None,
        under: list[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """VMs with snapshots across the vCenters, biggest first — for finding the space hogs.

        Snapshots are a top cause here: a forgotten one grows unbounded, fills
        the datastore, and slows every read through its redo chain. This lists
        the VMs that have them, with how much disk each is using (delta files
        plus the memory/state file), how old the oldest is, how deep the chain
        runs, and whether a failed delete left delta disks needing consolidation.

        Args:
            min_total_gb: only VMs whose snapshots use at least this many GB.
            older_than_hours: only VMs whose oldest snapshot is at least this old.
            min_count: only VMs with at least this many snapshots.
            only_problems: only VMs flagged over the warn/old/deep/consolidation thresholds.
            vcenters: vCenter names; all when empty.
            under: folder path segments to look under; everywhere when empty.
            limit: how many VMs to list (the counts cover all).

        """
        names = _names(fleet, vcenters)
        return await snapshots.find_vms_by_snapshot(
            fleet,
            resolved,
            names,
            min_total_gb=max(0.0, min_total_gb),
            older_than_hours=older_than_hours,
            min_count=max(1, min_count),
            only_problems=only_problems,
            under=[term for term in (under or []) if term.strip("/ ")],
            limit=max(1, min(limit, MAX_LIMIT)),
        )

    @tool()
    async def hardware_profile(
        *,
        vcenters: list[str] | None = None,
        under: list[str] | None = None,
        include_templates: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        """The whole fleet's virtual hardware, and the VMs that differ from their environment.

        Counts how many VMs carry each device category and each kind — NIC types,
        controllers, sound, anything unusual — and, within each environment, names
        the VMs whose hardware differs from their siblings (a different NIC type,
        an extra adapter, a missing device). Use this to see the hardware picture
        generically, without naming a device; find_vms_by_device is for when you
        already know what to look for.

        Args:
            vcenters: vCenter names; all when empty.
            under: folder path segments to look under; everywhere when empty.
            include_templates: also include template VMs.
            limit: how many environment outliers to list (the counts cover all).

        """
        names = _names(fleet, vcenters)
        return await hardware.hardware_profile(
            fleet,
            resolved,
            names,
            under=[term for term in (under or []) if term.strip("/ ")],
            include_templates=include_templates,
            limit=max(1, min(limit, MAX_LIMIT)),
        )

    @tool()
    async def check_host_time(
        *, vcenters: list[str] | None = None, measure_skew: bool = True
    ) -> dict[str, Any]:
        """Each ESXi host's NTP configuration and clock skew from vCenter, worst first.

        A drifting host clock breaks TLS handshakes and Kerberos/Active Directory
        token auth — a frequent root of the SSL/handshake errors clients hit,
        separate from session exhaustion (check_vcenters). Reads
        the NTP servers configured, whether the time service runs, and each host's
        own clock against vCenter's. Skew past ~300 s breaks AD auth outright.

        Args:
            vcenters: vCenter names; all when empty.
            measure_skew: also read each host's clock (one QueryDateTime per host)
                to measure skew; set False to read only the NTP configuration.

        """
        names = _names(fleet, vcenters)
        return await timecheck.check_host_time(fleet, resolved, names, measure_skew=measure_skew)

    @tool()
    async def find_resource_limits(
        *,
        kind: str = "all",
        vcenters: list[str] | None = None,
        under: list[str] | None = None,
        include_templates: bool = True,
        limit: int = 100,
    ) -> dict[str, Any]:
        """VMs throttled or constrained by a configured CPU/memory limit or reservation.

        A CPU limit caps a VM below its full speed and looks exactly like host CPU
        starvation without being it — the same symptom, a different fix. A memory
        limit below the VM's RAM forces balloon/swap; a large reservation locks
        capacity the cluster can no longer admit other VMs into, blocking
        power-ons. These ride on config, so a template passes them to every linked
        clone of it — templates are marked, since fixing the template fixes the
        clones.

        Args:
            kind: "limits", "reservations", or "all".
            vcenters: vCenter names; all when empty.
            under: folder path segments to look under; everywhere when empty.
            include_templates: also include template VMs (the usual root of a clone's limit).
            limit: how many VMs to list (the counts cover all).

        """
        if kind not in ("limits", "reservations", "all"):
            msg = 'kind must be "limits", "reservations", or "all"'
            raise ValueError(msg)
        names = _names(fleet, vcenters)
        return await resources.find_resource_limits(
            fleet,
            resolved,
            names,
            kind=kind,
            include_templates=include_templates,
            under=[term for term in (under or []) if term.strip("/ ")],
            limit=max(1, min(limit, MAX_LIMIT)),
        )

    @tool()
    async def check_datastores(
        *, vcenters: list[str] | None = None, only_problems: bool = False, limit: int = 100
    ) -> dict[str, Any]:
        """Every datastore's fill, thin over-provisioning, and per-host reachability (APD/PDL).

        When a datastore fills or a host loses its paths to it, every VM on it
        wedges at once — the layer above PowerFlex latency. Flags datastores
        nearly full (a thin disk then stalls on write), over-provisioned (thin
        disks could grow past capacity), or mounted-but-unreachable on a host
        (all-paths-down / permanent-device-loss). Datastores that hold a
        template's base disk are marked, since a linked clone reads its base from
        there and goes down with it.

        Args:
            vcenters: vCenter names; all when empty.
            only_problems: list only the troubled datastores, not every one.
            limit: how many datastores to list (the counts cover all).

        """
        names = _names(fleet, vcenters)
        return await storagehealth.check_datastores(
            fleet, resolved, names, only_problems=only_problems, limit=max(1, min(limit, MAX_LIMIT))
        )

    @tool()
    async def diagnose_window(
        *,
        vcenters: list[str] | None = None,
        since: str | None = None,
        until: str | None = None,
        minutes: int = 60,
    ) -> dict[str, Any]:
        """Resets, failed power-ons, host CPU and storage pressure over a past window.

        For incidents after the fact, when the VMs may already be destroyed:
        vCenter's events outlive the VMs they describe.

        Args:
            vcenters: vCenter names; all when empty.
            since: window start, ISO 8601 (UTC if no zone); default `minutes` before `until`.
            until: window end, ISO 8601; default now.
            minutes: window length when `since` is not given.

        """
        names = _names(fleet, vcenters)
        end = _since(until, datetime.now(UTC))
        begin = _since(since, end - timedelta(minutes=max(1, minutes)))
        return await scanning.diagnose_window(fleet, resolved, names, begin, end)


def _register_machine_tools(  # noqa: C901 - one closure per tool
    tool: Callable[..., Any], fleet: VCenterPool, resolved: Settings
) -> None:
    """Environments and machines: finding them, diagnosing them, and each piece on its own."""
    # -- environments and machines ----------------------------------------------

    @tool()
    async def find_environment(*, env_id: str, vcenter: str | None = None) -> dict[str, Any]:
        """Where an environment's folder is, on one vCenter or all, and its VMs.

        Matches a folder named by the env id (exactly, else containing it) and
        reports its full path and parent; ambiguity is reported, not resolved.

        Args:
            env_id: the environment id.
            vcenter: the vCenter, if known; every vCenter otherwise.

        """
        names = _names(fleet, [vcenter] if vcenter else None)

        def look(session: VCenterSession) -> list[dict[str, Any]]:
            layout = Layout.of(session)
            found = []
            for folder in environment_folders(layout.folders, env_id, resolved.env_parent_hints)[:10]:
                vms = read_vms(session, layout, root=session.reference("Folder", folder.moref))
                found.append(
                    {
                        "vcenter": session.vcenter.name,
                        "folder": folder.path,
                        "parent": folder.parent_name,
                        "exact": folder.name.lower() == env_id.strip().lower(),
                        "vms": [
                            {
                                "name": vm.name,
                                "moref": vm.moref,
                                "state": classify(vm, resolved.thresholds).state,
                            }
                            for vm, _ in vms
                        ],
                    }
                )
            return found

        results = await asyncio.gather(*(fleet.run(name, look) for name in names), return_exceptions=True)
        matches, errors = [], {}
        for name, result in zip(names, results, strict=True):
            if isinstance(result, BaseException):
                errors[name] = str(result)
            else:
                matches.extend(result)
        exact = [match for match in matches if match["exact"]]
        if len(exact) == 1:
            finding = f"found at {exact[0]['folder']} on {exact[0]['vcenter']}"
        elif not matches:
            finding = f"no folder named {env_id!r} or containing it (destroyed, or on an unread vCenter)"
        else:
            finding = f"{len(matches)} folders match {env_id!r}; pick by vCenter and path"
        return {"finding": finding, "matches": matches, "errors": errors}

    @tool("diagnose_vm")
    async def diagnose_vm_tool(
        *,
        vcenter: str,
        env_id: str | None = None,
        vm_name: str | None = None,
        moref: str | None = None,
        rebooted_at: str | None = None,
        console_captures: int = 2,
        console_interval_seconds: float = 10.0,
    ) -> dict[str, Any]:
        """Why one VM is stuck, on boot or after a reboot or hung mid-run.

        Every check in order, ending in the likely cause.

        Finds the VM by moref, or by env_id plus its name inside that
        environment (never by name alone). Then: machine state, CPU ready time
        and host demand, datastore and device latency, the virtual hardware and
        its connection state, the rest of its environment, how far the boot got
        in vmware.log, the serial console (EMS) if it has one, and the console
        screen (two captures).

        Pass rebooted_at (the time your orchestrator or monitoring logged the
        reboot or power-on you are investigating) when you have it: a guest reboot
        does not move vCenter's power-on time, so without it a warm-rebooted VM
        can look up for days and be misjudged as stuck. The result's
        machine.values.boot_time_source says what uptime was measured from
        (reported_reboot, reboot_event or power_on).

        Args:
            vcenter: any spelling of the vCenter's name (as your monitoring logs it).
            env_id: the environment id, with vm_name.
            vm_name: the machine's name inside its environment.
            moref: the VM's moref (vm-1234), instead of env_id and vm_name.
            rebooted_at: when the reboot happened, ISO 8601, from your orchestrator.
            console_captures: screenshots to take (0 to skip the console).
            console_interval_seconds: seconds between screenshots.

        """
        name = fleet.resolve(vcenter)
        captures = max(0, min(console_captures, 4))
        interval = _console_interval(resolved, captures, console_interval_seconds)
        rebooted = _parse_time(rebooted_at) if rebooted_at else None
        return await fleet.run(
            name,
            lambda session: diagnose_vm(
                session,
                resolved,
                env_id=env_id,
                vm_name=vm_name,
                moref=moref,
                rebooted_at=rebooted,
                console_captures=captures,
                console_interval_seconds=interval,
            ),
        )

    @tool("diagnose_environment")
    async def diagnose_environment_tool(*, vcenter: str, env_id: str) -> dict[str, Any]:
        """Every VM of one environment judged, grouped by host and datastore, with CPU and storage checks.

        Args:
            vcenter: any spelling of the vCenter's name.
            env_id: the environment id.

        """
        name = fleet.resolve(vcenter)
        return await fleet.run(name, lambda session: diagnose_environment(session, resolved, env_id=env_id))

    @tool("run_in_guest", annotations=GUEST_EXEC)
    async def run_in_guest_tool(
        *,
        vcenter: str,
        command: str,
        moref: str | None = None,
        env_id: str | None = None,
        vm_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> dict[str, Any]:
        """Run a command inside a guest OS and return its output and exit code. NOT read-only.

        This is the one tool that acts on a VM rather than only reading it: it
        executes `command` in the guest through VMware Tools, so it needs Tools
        running in the guest and guest-OS credentials (passed here, or the
        configured VSPHERE_GUEST_USERNAME/PASSWORD defaults). Use it for a
        diagnostic a read cannot answer — "is the guest actually responsive?",
        reading a file or a service state from inside — not for changes. Output
        is captured by redirecting to a temp file in the guest, downloading it,
        and deleting it (a small, temporary guest-filesystem write). The command
        is handed to the guest's own shell (`cmd.exe` on Windows, `/bin/sh` on
        Linux); a command containing the shell's quote character can break the
        wrapping.

        Find the VM by moref, or by env_id plus vm_name (never by name alone).

        Args:
            vcenter: the VM's vCenter.
            command: the command line to run in the guest.
            moref: the VM's moref, or give env_id and vm_name.
            env_id: the environment id, with vm_name.
            vm_name: the machine's name inside its environment.
            username: guest-OS account; the configured default when omitted.
            password: that account's password; the configured default when omitted.

        """
        name = fleet.resolve(vcenter)
        return await guestexec.run_in_guest(
            fleet,
            resolved,
            name,
            moref=moref,
            env_id=env_id,
            vm_name=vm_name,
            command=command,
            username=username,
            password=password,
        )


def _register_piece_tools(  # noqa: C901 - one closure per tool
    tool: Callable[..., Any], fleet: VCenterPool, resolved: Settings
) -> None:
    """One machine, piece by piece: its boot log, serial console, screen and events."""
    # -- one machine, piece by piece ----------------------------------------------

    async def _with_vm(
        vcenter: str, moref: str, work: Callable[[VCenterSession, Any, dict[str, Any]], dict[str, Any]]
    ) -> dict[str, Any]:
        name = fleet.resolve(vcenter)

        def run(session: VCenterSession) -> dict[str, Any]:
            located = locate(session, resolved, env_id=None, vm_name=None, moref=moref)
            if not located["found"]:
                return {"found": False, "reason": located["reason"]}
            vm = located["vm"]
            return {"vm": vm.identity()} | work(session, vm, located["row"])

        return await fleet.run(name, run)

    @tool()
    async def get_boot_timeline(*, vcenter: str, moref: str) -> dict[str, Any]:
        """How far the VM's last boot got, from vmware.log, and its serial console (EMS) if any.

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref.

        """
        return await _with_vm(
            vcenter,
            moref,
            lambda session, vm, row: {
                "boot": read_logs(session, resolved, vm, row),
                "serial_console": read_serial_files(session, vm),
            },
        )

    @tool()
    async def read_vm_log(
        *,
        vcenter: str,
        moref: str,
        which: int = 0,
        pattern: str | None = None,
        all_lines: bool = False,
        since: str | None = None,
        tail: int = 200,
    ) -> dict[str, Any]:
        """Lines of a VM's vmware.log (or a rotated vmware-N.log), filtered on the server.

        Without a pattern, only boot-relevant lines are returned (power, reset,
        firmware, drivers, Tools, faults, storage, questions).

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref.
            which: 0 for vmware.log, N for vmware-N.log (older).
            pattern: a regular expression to keep lines by, case-insensitive.
            all_lines: return every line instead of the boot-relevant ones.
            since: only lines at or after this ISO 8601 time.
            tail: how many of the newest matching lines to return.

        """
        if pattern:
            re.compile(pattern)
        limit = max(1, min(tail, resolved.max_log_lines))

        def work(session: VCenterSession, vm: Any, row: dict[str, Any]) -> dict[str, Any]:
            folder = vm_folder(row, vm)
            datacenter = vm.datacenter_path or vm.datacenter
            if folder is None or datacenter is None:
                return {"available": False, "reason": "the VM's folder or datacenter is not known"}
            file = "vmware.log" if which == 0 else f"vmware-{which}.log"
            read = session.read_datastore_file(datacenter, f"{folder}/{file}", resolved.max_log_bytes)
            if read.status != 200:  # noqa: PLR2004
                return {"available": False, "reason": f"{file} not readable (HTTP {read.status})"}
            lines = parse_lines(read.text)
            moment = _since(since, datetime.min.replace(tzinfo=UTC)) if since else None
            kept, total = grep(lines, ".*" if all_lines else pattern, since=moment, limit=limit)
            return {
                "available": True,
                "path": f"{folder}/{file}",
                "bytes": read.size,
                "read_only_the_end": read.truncated,
                "matched": total,
                "returned": len(kept),
                "lines": [line.as_dict() for line in kept],
            }

        return await _with_vm(vcenter, moref, work)

    @tool()
    async def read_serial_console(*, vcenter: str, moref: str, tail: int = 80) -> dict[str, Any]:
        """The VM's serial console file: Windows EMS or a Linux kernel console, if it has one.

        Reports stop codes (with the layer each usually points at) and kernel
        errors. A VM with no serial port to a file is reported as such; that is
        normal and not a failure.

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref.
            tail: lines from the end of each file.

        """
        lines = max(1, min(tail, resolved.max_log_lines))
        return await _with_vm(
            vcenter, moref, lambda session, vm, _row: read_serial_files(session, vm, tail_lines=lines)
        )

    @tool()
    async def get_vm_console(
        *,
        vcenter: str,
        moref: str,
        captures: int = 2,
        interval_seconds: float = 10.0,
        include_image: bool = False,
    ) -> dict[str, Any]:
        """The console screen, read into words: black, frozen or changing, blue screen, OCR text.

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref.
            captures: screenshots to take (1 to 4).
            interval_seconds: seconds between them.
            include_image: also return the last capture, downscaled, as base64 JPEG.

        """
        count = max(1, min(captures, 4))
        interval = _console_interval(resolved, count, interval_seconds)

        def work(session: VCenterSession, vm: Any, _row: dict[str, Any]) -> dict[str, Any]:
            result = read_console(session, resolved, vm, captures=count, interval_seconds=interval)
            if include_image and result.get("available"):
                status, body, _ = session.screenshot(vm.moref)
                if status == 200:  # noqa: PLR2004
                    result["image_jpeg_base64"] = _thumbnail(body)
            return result

        return await _with_vm(vcenter, moref, work)

    @tool()
    async def get_vm_events(*, vcenter: str, moref: str, minutes: int = 120) -> dict[str, Any]:
        """The VM's vCenter events (power, reset, migration, HA, reconfigure, messages).

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref, while the VM exists; for a destroyed VM use diagnose_window.
            minutes: how far back.

        """
        name = fleet.resolve(vcenter)

        def run(session: VCenterSession) -> dict[str, Any]:
            now = session.now()
            try:
                events = session.events(
                    entity=session.reference("VirtualMachine", moref),
                    begin=now - timedelta(minutes=max(1, minutes)),
                    end=now,
                )
            except vmodl.fault.ManagedObjectNotFound:
                return {
                    "vcenter": name,
                    "moref": moref,
                    "found": False,
                    "reason": (
                        f"{moref} no longer exists, so its events cannot be queried by entity; use "
                        "diagnose_window over the time it existed to see what happened to the environment"
                    ),
                }
            return {"vcenter": name, "moref": moref, "count": len(events), "events": summarize_events(events)}

        return await fleet.run(name, run)

    @tool()
    async def get_vm_hardware(*, vcenter: str, moref: str) -> dict[str, Any]:
        """The VM's virtual hardware and each device's connection state.

        Lists the virtual adapters, controllers, disks, CD-ROM, sound, serial,
        USB and video the VM has, and vCenter's view of whether each connectable
        device is connected — all read-only, with no Tools. Flags a disconnected
        network adapter, a mounted ISO or a device in an error state, any of
        which can stop a boot. This is the *virtual* hardware and vCenter's view;
        whether the guest's driver for a device loaded is inside the guest (needs
        Tools), and the boot timeline reads the drivers announcing themselves in
        vmware.log as the outside-in proxy for that.

        Args:
            vcenter: the VM's vCenter.
            moref: the VM's moref.

        """

        def work(_session: VCenterSession, vm: Any, _row: dict[str, Any]) -> dict[str, Any]:
            return {
                "devices": vm.devices,
                "findings": vm.device_findings or ["no hardware issue stood out"],
                "note": "virtual hardware and vCenter's connection view; guest driver status needs Tools",
            }

        return await _with_vm(vcenter, moref, work)


def _register_infrastructure_tools(tool: Callable[..., Any], fleet: VCenterPool, resolved: Settings) -> None:
    """Hosts, datastores and host logs."""
    # -- the infrastructure ----------------------------------------------------------

    @tool()
    async def get_host_health(*, vcenter: str, host: str, minutes: int = 30) -> dict[str, Any]:
        """One ESXi host: CPU demand against capacity, its storage latency, and its VMs' states.

        Args:
            vcenter: the host's vCenter.
            host: its name or moref.
            minutes: the window to read counters over.

        """
        name = fleet.resolve(vcenter)

        def run(session: VCenterSession) -> dict[str, Any]:
            layout = Layout.of(session)
            found = _pick(layout.hosts.values(), host, lambda item: (item.name, item.moref))
            now = session.now()
            begin = now - timedelta(minutes=max(1, min(minutes, 24 * 60)))
            cpu, unknown = hosts_cpu(session, [found], begin=begin, end=now, thresholds=resolved.thresholds)
            rows = session.retrieve(
                vim.HostSystem, ("datastore",), objects=[session.reference("HostSystem", found.moref)]
            )
            mounted = {ref._moId for ref in (rows[0].get("datastore") or [])} if rows else set()  # noqa: SLF001
            disk = storage(
                session,
                {found.moref: found.name},
                [store for moref, store in layout.datastores.items() if moref in mounted],
                begin=begin,
                end=now,
                thresholds=resolved.thresholds,
            )
            vms = [
                vm for vm, _ in read_vms(session, layout, root=session.reference("HostSystem", found.moref))
            ]
            verdicts = {vm.moref: classify(vm, resolved.thresholds) for vm in vms}
            return {
                "host": found.name,
                "moref": found.moref,
                "cluster": found.cluster,
                "connection_state": found.connection_state,
                "maintenance": found.maintenance,
                "cpu": cpu.get(found.moref),
                "cpu_counters_unavailable": unknown,
                "storage": disk,
                "vms": len(vms),
                "vm_states": count_states(verdicts),
                "abnormal_vms": [
                    vm.identity() | {"verdict": verdicts[vm.moref].as_dict()}
                    for vm in vms
                    if verdicts[vm.moref].abnormal
                ][:50],
            }

        return await fleet.run(name, run)

    @tool()
    async def get_datastore_health(*, vcenter: str, datastore: str, minutes: int = 30) -> dict[str, Any]:
        """One datastore: latency and IOPS from every host mounting it, free space, its VMs' states.

        Args:
            vcenter: the datastore's vCenter.
            datastore: its name or moref.
            minutes: the window to read counters over.

        """
        name = fleet.resolve(vcenter)

        def run(session: VCenterSession) -> dict[str, Any]:
            layout = Layout.of(session)
            found = _pick(layout.datastores.values(), datastore, lambda item: (item["name"], item["moref"]))
            rows = session.retrieve(vim.Datastore, ("host", "vm"), objects=[found["_ref"]])
            mounts = rows[0].get("host") or [] if rows else []
            host_ids = [mount.key._moId for mount in mounts]  # noqa: SLF001
            now = session.now()
            begin = now - timedelta(minutes=max(1, min(minutes, 24 * 60)))
            disk = storage(
                session,
                {moref: layout.hosts[moref].name for moref in host_ids if moref in layout.hosts},
                [found],
                begin=begin,
                end=now,
                thresholds=resolved.thresholds,
            )
            vm_refs = list(rows[0].get("vm") or []) if rows else []
            vms = [vm for vm, _ in read_vms(session, layout, objects=vm_refs)] if vm_refs else []
            verdicts = {vm.moref: classify(vm, resolved.thresholds) for vm in vms}
            return {
                "datastore": found["name"],
                "moref": found["moref"],
                "type": found.get("type"),
                "accessible": found.get("accessible"),
                "hosts_mounting": len(host_ids),
                "storage": disk,
                "vms": len(vms),
                "vm_states": count_states(verdicts),
                "abnormal_vms": [
                    vm.identity() | {"verdict": verdicts[vm.moref].as_dict()}
                    for vm in vms
                    if verdicts[vm.moref].abnormal
                ][:50],
            }

        return await fleet.run(name, run)

    @tool()
    async def read_host_log(
        *,
        vcenter: str,
        host: str,
        log: str = "vmkernel",
        pattern: str | None = None,
        lines: int = 2000,
        limit: int = 200,
    ) -> dict[str, Any]:
        """Lines from an ESXi host's log (vmkernel, hostd, vpxa), filtered on the server.

        Args:
            vcenter: the host's vCenter.
            host: its name or moref.
            log: the log key; the result lists the keys offered when one is not.
            pattern: a regular expression to keep lines by; all lines when empty.
            lines: how many of the last lines to read.
            limit: how many matching lines to return.

        """
        if pattern:
            re.compile(pattern)
        name = fleet.resolve(vcenter)

        def run(session: VCenterSession) -> dict[str, Any]:
            layout = Layout.of(session)
            found = _pick(layout.hosts.values(), host, lambda item: (item.name, item.moref))
            read = session.host_log(
                session.reference("HostSystem", found.moref), log, max(10, min(lines, 20000))
            )
            if not read.get("available"):
                return {"host": found.name} | read
            parsed = parse_lines("\n".join(read["lines"]), first_number=read["line_start"])
            kept, total = grep(parsed, pattern or ".*", limit=max(1, min(limit, resolved.max_log_lines)))
            return {
                "host": found.name,
                "log": log,
                "lines_read": len(parsed),
                "matched": total,
                "lines": [line.as_dict() for line in kept],
            }

        return await fleet.run(name, run)


def _register_vrops_tools(tool: Callable[..., Any], vrops: Vrops) -> None:
    """vROps: history for hosts, clusters and datastores. Only when configured."""

    @tool()
    async def vrops_find_resource(*, name: str, kind: str | None = None) -> dict[str, Any]:
        """A vROps resource (host, cluster, datastore, VM) by name, with the id other vROps tools take.

        Args:
            name: the object's name, as vCenter shows it.
            kind: HostSystem, ClusterComputeResource, Datastore or VirtualMachine.

        """
        if kind and kind not in KINDS:
            msg = f"kind must be one of {', '.join(KINDS)}"
            raise ValueError(msg)
        found = await vrops.find(name, kind)
        return {
            "resources": found,
            "suggested_stat_keys": SUGGESTED_STAT_KEYS.get(kind or "", ()),
            "note": "stat keys vary by version: check them with vrops_list_stat_keys",
        }

    @tool()
    async def vrops_list_stat_keys(*, resource_id: str, contains: str | None = None) -> dict[str, Any]:
        """The stat keys a vROps resource actually has, optionally filtered (e.g. "latency").

        Args:
            resource_id: from vrops_find_resource.
            contains: keep keys containing this text.

        """
        keys = await vrops.stat_keys(resource_id, contains)
        return {"count": len(keys), "keys": keys[:300]}

    @tool()
    async def vrops_get_stats(
        *,
        resource_id: str,
        stat_keys: list[str],
        since: str | None = None,
        until: str | None = None,
        hours: float = 24.0,
        interval_minutes: int = 5,
    ) -> dict[str, Any]:
        """A resource's stats over a window: max, mean and when they peaked, per key.

        Args:
            resource_id: from vrops_find_resource.
            stat_keys: keys to read (from vrops_list_stat_keys).
            since: window start, ISO 8601; default `hours` before `until`.
            until: window end, ISO 8601; default now.
            hours: window length when `since` is not given.
            interval_minutes: rollup interval.

        """
        end = _since(until, datetime.now(UTC))
        begin = _since(since, end - timedelta(hours=max(0.1, min(hours, 24 * 31))))
        series = await vrops.stats(
            resource_id, stat_keys, begin, end, interval_minutes=max(1, interval_minutes)
        )
        result = {}
        for key in stat_keys:
            samples = series.get(key, [])
            if not samples:
                result[key] = {"available": False}
                continue
            peak_at, peak = max(samples, key=lambda sample: sample[1])
            values = [value for _, value in samples]
            result[key] = {
                "max": peak,
                "peak_at": peak_at,
                "mean": sum(values) / len(values),
                "last": values[-1],
                "samples": len(values),
                "series": [[stamp, value] for stamp, value in samples[-200:]],
            }
        return {"window": {"from": begin, "to": end}, "stats": result}

    @tool()
    async def vrops_compare_window(
        *,
        resource_id: str,
        stat_keys: list[str],
        since: str,
        until: str,
        baseline_days: int = 7,
        interval_minutes: int = 5,
    ) -> dict[str, Any]:
        """Is this window unusual? The same clock window on each previous day, against this one.

        Args:
            resource_id: from vrops_find_resource.
            stat_keys: keys to compare.
            since: window start, ISO 8601.
            until: window end, ISO 8601.
            baseline_days: how many previous days.
            interval_minutes: rollup interval.

        """
        begin = _since(since, datetime.now(UTC))
        end = _since(until, datetime.now(UTC))
        compared = await vrops.compare(
            resource_id,
            stat_keys,
            begin,
            end,
            baseline_days=max(1, min(baseline_days, 30)),
            interval_minutes=max(1, interval_minutes),
        )
        findings = [
            f"{key}: window max {entry['window_max']} is above every one of the last "
            f"{len(entry['baseline_days'])} days"
            if entry.get("unusual")
            else f"{key}: window max {entry['window_max']} was matched or beaten on "
            f"{entry['days_as_high_or_higher']} of the last {len(entry['baseline_days'])} days"
            for key, entry in compared.items()
            if "window_max" in entry
        ]
        return {"window": {"from": begin, "to": end}, "findings": findings, "stats": compared}

    @tool()
    async def vrops_get_alerts(*, resource_id: str, hours: float = 24.0) -> dict[str, Any]:
        """Alerts on a vROps resource that started or changed in the last hours.

        Args:
            resource_id: from vrops_find_resource.
            hours: how far back.

        """
        since = datetime.now(UTC) - timedelta(hours=max(0.1, hours))
        alerts = await vrops.alerts(resource_id, since)
        return {"count": len(alerts), "alerts": alerts[:100]}


def _pick[T](items: Any, wanted: str, keys: Callable[[T], tuple[str, str]]) -> T:
    """One object by name or moref, case-insensitively; an error naming near misses."""
    text = wanted.strip().lower()
    pool = list(items)
    exact = [item for item in pool if text in (key.lower() for key in keys(item) if key)]
    if len(exact) == 1:
        return exact[0]
    if not exact:
        near = [keys(item)[0] for item in pool if text in (keys(item)[0] or "").lower()][:10]
        msg = f"{wanted!r} not found" + (f"; similar: {', '.join(near)}" if near else "")
        raise LookupError(msg)
    msg = f"{wanted!r} matches {len(exact)} objects; use the moref"
    raise LookupError(msg)


def _console_interval(settings: Settings, captures: int, asked: float) -> float:
    """Seconds between screenshots, kept inside a third of the call's deadline."""
    gaps = max(1, captures - 1)
    return max(1.0, min(asked, 30.0, settings.timeout_seconds / 3 / gaps))


def _thumbnail(data: bytes) -> str:
    with Image.open(io.BytesIO(data)) as image:
        copy = image.convert("RGB")
    copy.thumbnail((800, 600))
    buffer = io.BytesIO()
    copy.save(buffer, format="JPEG", quality=60)
    return base64.b64encode(buffer.getvalue()).decode("ascii")
