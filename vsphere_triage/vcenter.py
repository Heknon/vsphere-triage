"""One session per vCenter, and the handful of reads everything else is built from.

pyVmomi blocks, so each read runs in a worker thread, at most
`VSPHERE_MAX_CONCURRENT_PER_VCENTER` at a time per vCenter, under the server's
own deadline. Every call goes through `ReadOnlyStub`; every HTTP request (a
datastore file, the console screen) through `ensure_read_request`.

Properties are always read through the property collector, naming the paths
wanted, so a scan of a vCenter is one round trip per few hundred objects and
not one per property. A property the server did not return is simply absent
from the result: vCenter omits unset properties, and a simulator omits more.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import logging
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import quote

import httpx
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl

from vsphere_triage.readonly import ReadOnlyStub, ensure_read_request

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from vsphere_triage.config import Settings, VCenter

logger = logging.getLogger(__name__)

T = TypeVar("T")

PAGE_SIZE = 500
# QueryEvents answers with at most this many events, the newest; a busier
# window is cut, and results that use it say so.
QUERY_EVENTS_CAP = 1000
TASK_POLL_SECONDS = 0.1
REALTIME_INTERVAL_SECONDS = 20
HISTORICAL_INTERVAL_SECONDS = 300
# vCenter keeps 20-second samples for about an hour; older windows come from
# the first historical rollup, if the statistics level kept the counter at all.
REALTIME_SPAN = timedelta(minutes=60)
# vCenter refuses a historical query naming more entity-counter pairs than
# `config.vpxd.stats.maxQueryMetrics` (64 by default); realtime comes from the
# hosts and has no such limit, but is still sent in batches to bound each reply.
HISTORICAL_METRICS_PER_QUERY = 64
REALTIME_ENTITIES_PER_QUERY = 50


class VSphereError(RuntimeError):
    """A vSphere read failed in a way the caller should see, worded for a reader."""


@dataclass
class DatastoreFile:
    """A file read from a datastore: possibly only its end, and said so."""

    path: str
    text: str
    size: int | None
    truncated: bool
    status: int


@dataclass
class PerfSeries:
    """One counter on one entity: samples per instance, oldest first."""

    counter: str
    unit: str
    interval_seconds: int
    samples: dict[str, list[tuple[datetime, float]]] = field(default_factory=dict)


def ssl_context(settings: Settings) -> ssl.SSLContext:
    """The TLS context for vCenter: verified, unless explicitly turned off."""
    if not settings.tls_verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=settings.ca_bundle)


def session_cookie(raw: str) -> str:
    """The `name=value` pair of the SOAP session cookie, for HTTP endpoints."""
    return raw.split(";", 1)[0].strip()


def parse_datastore_path(path: str) -> tuple[str, str]:
    """Split `[datastore] folder/file` into the datastore and the path inside it."""
    text = path.strip()
    if not text.startswith("[") or "]" not in text:
        msg = f"Not a datastore path: {path!r}"
        raise ValueError(msg)
    name, rest = text[1:].split("]", 1)
    return name.strip(), rest.strip()


def _declared_size(response: httpx.Response, *, ranged: bool) -> int | None:
    """The file's full size from the headers: `Content-Range` for a 206, else `Content-Length`.

    A 206's `Content-Length` is the slice, not the file; its full size is the
    number after the slash in `Content-Range: bytes START-END/TOTAL`.
    """
    if ranged:
        content_range = response.headers.get("content-range", "")
        if "/" in content_range:
            whole = content_range.rsplit("/", 1)[1].strip()
            if whole.isdigit():
                return int(whole)
        return None
    declared = response.headers.get("content-length")
    return int(declared) if declared and declared.isdigit() else None


def _session_row(entry: Any, now: datetime) -> dict[str, Any]:
    """One UserSession flattened: who, from where, how old and how idle."""
    login = as_utc(entry.loginTime) if getattr(entry, "loginTime", None) else None
    active = as_utc(entry.lastActiveTime) if getattr(entry, "lastActiveTime", None) else None
    agent = (getattr(entry, "userAgent", None) or "").split(" ", 1)[0] or "unknown"
    return {
        "user": entry.userName,
        "ip": getattr(entry, "ipAddress", None),
        "user_agent": agent,
        "extension": bool(getattr(entry, "extensionSession", False)),
        "call_count": getattr(entry, "callCount", None),
        "login_time": login,
        "age_minutes": round((now - login).total_seconds() / 60, 1) if login else None,
        "idle_minutes": round((now - active).total_seconds() / 60, 1) if active else None,
    }


def _tally(rows: list[dict[str, Any]], key: Callable[[dict[str, Any]], str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        name = key(row)
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def _top(counts: dict[str, int], keep: int = 15) -> dict[str, int]:
    return dict(list(counts.items())[:keep])


class VCenterSession:
    """A logged-in, read-only session on one vCenter. Not thread-safe to create."""

    def __init__(self, vcenter: VCenter, settings: Settings) -> None:
        """Connect lazily: nothing is sent until the first read."""
        self.vcenter = vcenter
        self.settings = settings
        self._service: Any = None
        self._content: Any = None
        self._stub: ReadOnlyStub | None = None
        self._http: httpx.Client | None = None
        self._counters: dict[str, Any] | None = None
        self._raw: Any = None
        # Guards every login and logout, so concurrent worker threads cannot open
        # two sessions or stomp each other's. `generation` rises on each login, so
        # a caller can tell whether the session it used has since been replaced.
        self._lock = threading.Lock()
        self.generation = 0

    # -- the session ---------------------------------------------------------

    def _login(self) -> None:
        """Open a fresh session, disconnecting any old one first. Call under `_lock`."""
        username, password = self.settings.credentials_for(self.vcenter)
        try:
            raw = SmartConnect(
                host=self.vcenter.host,
                port=self.vcenter.port,
                user=username,
                pwd=password,
                sslContext=ssl_context(self.settings),
                connectionPoolTimeout=int(self.settings.timeout_seconds),
                # A read timeout on the SOAP socket: a vCenter that stalls mid-reply
                # raises instead of blocking the worker thread forever, which would
                # otherwise leak threads until every tool queues behind them.
                httpConnectionTimeout=self.settings.timeout_seconds,
            )
        except vim.fault.InvalidLogin as error:
            msg = f"vCenter {self.vcenter.name}: login refused for {username!r}"
            raise VSphereError(msg) from error
        except (OSError, ssl.SSLError) as error:
            msg = f"vCenter {self.vcenter.name} ({self.vcenter.host}) unreachable: {error}"
            raise VSphereError(msg) from error
        self._teardown()
        self._stub = ReadOnlyStub(raw._stub)  # noqa: SLF001 - wrapping is the point
        self._service = vim.ServiceInstance("ServiceInstance", self._stub)
        self._content = self._service.RetrieveContent()
        self._raw = raw
        self._http = httpx.Client(
            verify=ssl_context(self.settings),
            timeout=self.settings.timeout_seconds,
            follow_redirects=False,
            # Deliberate transport: the session cookie is the only credential, and no
            # ambient HTTPS_PROXY/NO_PROXY or ~/.netrc reroutes an internal read or
            # attaches another credential to it.
            trust_env=False,
        )
        self.generation += 1

    def _teardown(self) -> None:
        """Close the HTTP client and log the current session out. Call under `_lock`."""
        if self._http is not None:
            with contextlib.suppress(Exception):
                self._http.close()
            self._http = None
        if self._raw is not None:
            with contextlib.suppress(Exception):
                Disconnect(self._raw)
            self._raw = None
        self._service = None
        self._content = None
        self._counters = None

    def connect(self) -> None:
        """Log in if not already connected. Safe to call from several threads."""
        if self._content is not None:
            return
        with self._lock:
            if self._content is None:
                self._login()

    def reconnect(self, seen_generation: int) -> None:
        """Log in afresh after a session expiry, unless another caller already did.

        `seen_generation` is the generation the caller was using; if it has moved,
        someone has already reconnected and this is a no-op, so concurrent callers
        do not log each other's new sessions out.
        """
        with self._lock:
            if self.generation == seen_generation:
                self._login()

    def close(self) -> None:
        """Log out and drop the HTTP client; safe to call twice."""
        with self._lock:
            self._teardown()

    @property
    def content(self) -> Any:
        """The service content, connecting first if needed."""
        if self._content is None:
            self.connect()
        return self._content

    @property
    def methods_seen(self) -> set[str]:
        """Every vSphere method this session has sent, for the read-only test."""
        return set(self._stub.seen) if self._stub else set()

    def about(self) -> dict[str, Any]:
        """Which vCenter this is: product, version, build, and its clock."""
        about = self.content.about
        return {
            "name": self.vcenter.name,
            "host": self.vcenter.host,
            "product": about.fullName,
            "version": about.version,
            "build": about.build,
            "api_version": about.apiVersion,
            "instance_uuid": getattr(about, "instanceUuid", None),
            "clock": as_utc(self._service.CurrentTime()),
        }

    def session_count(self) -> dict[str, Any]:
        """How many sessions this vCenter has open, the headline for check_vcenters.

        A read-only role may not be allowed the global session list; then only
        this server's own session is visible and the result says so. The count
        is the signal for connection/session exhaustion that causes SSL EOFs and
        resets for every client hitting the vCenter, this server included.
        """
        manager = self.content.sessionManager
        current = getattr(manager.currentSession, "userName", None) if manager.currentSession else None
        try:
            sessions = manager.sessionList or []
        except vim.fault.NoPermission:
            return {
                "visible": "own_only",
                "note": "the account may not list all sessions; grant Sessions.View to see the global count",
                "current_user": current,
            }
        by_user: dict[str, int] = {}
        for entry in sessions:
            by_user[entry.userName] = by_user.get(entry.userName, 0) + 1
        return {
            "visible": "all",
            "total": len(sessions),
            "by_user": dict(sorted(by_user.items(), key=lambda kv: kv[1], reverse=True)[:15]),
            "current_user": current,
        }

    def sessions(self) -> dict[str, Any]:
        """Every open API session grouped to show who is holding them, and likely leaks.

        For diagnosing session/connection exhaustion: sessions grouped by user,
        by source IP, and by (user, IP, client) with how many are idle and how
        old they are. A single source holding a large share, or many idle
        sessions from one client, is the usual cause — a client that opens
        sessions and never closes them. Needs the account to be allowed the
        global session list; otherwise only this server's own session shows.

        Also reports the configured idle timeout and, where readable, the
        session limit, so the count can be read against the ceiling.
        """
        manager = self.content.sessionManager
        now = as_utc(self._service.CurrentTime())
        try:
            raw = manager.sessionList or []
        except vim.fault.NoPermission:
            return {
                "visible": "own_only",
                "note": (
                    "this account may not list all sessions; grant the Sessions.View privilege (or a role "
                    "that carries it) to diagnose exhaustion, or read the vCenter's session count from vROps"
                ),
                "current_user": getattr(manager.currentSession, "userName", None),
            }
        idle_cut = self._session_timeout_minutes()
        rows = [_session_row(entry, now) for entry in raw]
        by_user = _tally(rows, lambda row: row["user"])
        by_ip = _tally(rows, lambda row: row["ip"] or "unknown")
        by_client = _tally(rows, lambda row: f"{row['user']} @ {row['ip']} ({row['user_agent']})")
        threshold = idle_cut or 30
        idle = [row for row in rows if row["idle_minutes"] is not None and row["idle_minutes"] >= threshold]
        findings = []
        if rows:
            top_source, top_count = max(by_client.items(), key=lambda kv: kv[1])
            share = top_count / len(rows)
            if share >= 0.5 and top_count >= 10:  # noqa: PLR2004
                findings.append(
                    f"{top_count} of {len(rows)} sessions ({share:.0%}) are {top_source} — "
                    "one client holding most of them points at a session leak there"
                )
            if len(idle) >= 10:  # noqa: PLR2004
                idle_sources = _tally(idle, lambda row: f"{row['user']} @ {row['ip']}")
                worst = ", ".join(f"{src} ({count})" for src, count in list(idle_sources.items())[:3])
                findings.append(
                    f"{len(idle)} sessions idle past the {idle_cut or 30:g}-min timeout; most from {worst} — "
                    "idle sessions that never close are the classic leak"
                )
        return {
            "visible": "all",
            "total": len(rows),
            "idle_timeout_minutes": idle_cut,
            "idle_sessions": len(idle),
            "by_user": _top(by_user),
            "by_source_ip": _top(by_ip),
            "by_client": _top(by_client),
            "findings": findings or ["no single client dominates the open sessions"],
            "oldest": sorted(
                (row for row in rows if row["age_minutes"] is not None),
                key=lambda row: row["age_minutes"],
                reverse=True,
            )[:10],
        }

    def _session_timeout_minutes(self) -> float | None:
        """The configured API idle-session timeout, if the setting is readable."""
        with contextlib.suppress(Exception):
            values = self.content.setting.QueryOptions("config.vmacore.soap.sessionTimeout")
            if values and isinstance(values[0].value, (int, float)):
                return float(values[0].value) / 60
        return None

    def now(self) -> datetime:
        """VCenter's own clock, which every window on this vCenter is measured by."""
        _ = self.content
        return as_utc(self._service.CurrentTime())

    # -- properties ----------------------------------------------------------

    def retrieve(
        self,
        kind: type,
        paths: Sequence[str],
        *,
        root: Any = None,
        objects: Iterable[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Read `paths` from every `kind` under `root`, or from the given objects.

        Each row carries `_ref` (the object), `moref` and whichever paths came
        back. `_missing` names paths the server withheld (usually permission)
        or does not have at all (an older vCenter): a path vCenter rejects is
        dropped and the read retried, rather than failing every VM for one
        property. An object listed by hand that no longer exists (a destroyed
        VM) is dropped the same way.
        """
        wanted = list(paths)
        listed = list(objects) if objects is not None else None
        rejected: list[str] = []
        for _ in range(len(wanted) + (len(listed) if listed else 0) + 1):
            if listed is not None and not listed:
                return []
            try:
                rows = self._retrieve_once(kind, wanted, root=root, objects=listed)
            except vmodl.query.InvalidProperty as fault:
                name = getattr(fault, "name", None)
                if not name or name not in wanted:
                    raise
                wanted.remove(name)
                rejected.append(name)
                continue
            except vmodl.fault.ManagedObjectNotFound as fault:
                gone = getattr(getattr(fault, "obj", None), "_moId", None)
                if listed is None or gone is None:
                    raise
                listed = [item for item in listed if item._moId != gone]  # noqa: SLF001
                continue
            if rejected:
                for row in rows:
                    row["_missing"] = [*row.get("_missing", []), *rejected]
            return rows
        msg = "Property read did not settle after dropping rejected paths"
        raise VSphereError(msg)

    def _retrieve_once(
        self, kind: type, paths: list[str], *, root: Any, objects: list[Any] | None
    ) -> list[dict[str, Any]]:
        content = self.content
        view = None
        if objects is not None:
            object_set = [vmodl.query.PropertyCollector.ObjectSpec(obj=item, skip=False) for item in objects]
        else:
            view = content.viewManager.CreateContainerView(root or content.rootFolder, [kind], recursive=True)
            traversal = vmodl.query.PropertyCollector.TraversalSpec(
                name="view", path="view", skip=False, type=vim.view.ContainerView
            )
            object_set = [
                vmodl.query.PropertyCollector.ObjectSpec(obj=view, skip=True, selectSet=[traversal])
            ]
        spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=object_set,
            propSet=[vmodl.query.PropertyCollector.PropertySpec(type=kind, pathSet=paths, all=False)],
        )
        collector = content.propertyCollector
        rows: list[dict[str, Any]] = []
        try:
            result = collector.RetrievePropertiesEx(
                [spec], vmodl.query.PropertyCollector.RetrieveOptions(maxObjects=PAGE_SIZE)
            )
            while result is not None:
                rows.extend(_rows(result.objects))
                token = result.token
                if not token:
                    break
                result = collector.ContinueRetrievePropertiesEx(token)
        finally:
            if view is not None:
                with contextlib.suppress(Exception):
                    view.DestroyView()
        return rows

    def reference(self, kind: str, moref: str) -> Any:
        """A managed object by type and id, bound to this session's read-only stub."""
        _ = self.content
        return getattr(vim, kind)(moref, self._stub)

    def host_datetime(self, datetime_system_moref: str) -> datetime:
        """One host's own clock, read through its dateTimeSystem (QueryDateTime, read-only)."""
        system = self.reference("HostDateTimeSystem", datetime_system_moref)
        return as_utc(system.QueryDateTime())

    def run_in_guest(
        self,
        moref: str,
        *,
        windows: bool,
        command: str,
        username: str,
        password: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> dict[str, Any]:
        """Run a command in the guest and return its exit code and output. NOT read-only.

        This is the single operation that bypasses `ReadOnlyStub`: it goes through
        the raw SOAP stub on purpose, because the user has allowed commands on the
        VM for diagnostics. Output is captured by redirecting to a guest temp file,
        downloading it, and deleting it. Needs VMware Tools in the guest.
        """
        # Local import: guestexec imports diagnose, which imports this module.
        from vsphere_triage.guestexec import (  # noqa: PLC0415 - deferred to avoid a circular import
            guest_program_spec,
            guest_temp_path,
            rewrite_transfer_url,
        )

        _ = self.content
        if self._raw is None:
            msg = "Session is not connected"
            raise VSphereError(msg)
        raw_stub = self._raw._stub  # noqa: SLF001 - the deliberate unguarded path for guest exec
        manager = vim.GuestOperationsManager(self.content.guestOperationsManager._moId, raw_stub)  # noqa: SLF001  # ty: ignore[unresolved-attribute] - pyVmomi builds vim.* types dynamically
        process_manager = manager.processManager
        file_manager = manager.fileManager
        vm = vim.VirtualMachine(moref, raw_stub)
        auth = vim.vm.guest.NamePasswordAuthentication(
            username=username, password=password, interactiveSession=False
        )
        token = uuid.uuid4().hex
        out_path = guest_temp_path(token, windows=windows)
        program_path, arguments = guest_program_spec(command, out_path, windows=windows)
        spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program_path, arguments=arguments)
        pid = process_manager.StartProgramInGuest(vm, auth, spec)
        deadline = time.monotonic() + timeout_seconds
        exit_code: int | None = None
        while time.monotonic() < deadline:
            infos = process_manager.ListProcessesInGuest(vm, auth, [pid]) or []
            info = next((item for item in infos if item.pid == pid), None)
            if info is not None and info.exitCode is not None:
                exit_code = info.exitCode
                break
            time.sleep(0.5)
        terminated = False
        if exit_code is None:
            # Stop it rather than leave it running unwatched, still writing to a
            # file about to be read and deleted.
            with contextlib.suppress(Exception):
                process_manager.TerminateProcessInGuest(vm, auth, pid)
                terminated = True
        output, truncated = "", False
        try:
            transfer = file_manager.InitiateFileTransferFromGuest(vm, auth, out_path)
            output, truncated = self._download_text(
                rewrite_transfer_url(transfer.url, self.vcenter.host), max_output_bytes
            )
        finally:
            with contextlib.suppress(Exception):
                file_manager.DeleteFileInGuest(vm, auth, out_path)
        return {
            "command": command,
            "ran_as": username,
            "pid": pid,
            "exit_code": exit_code,
            "timed_out": exit_code is None,
            "terminated_after_timeout": terminated,
            "output": output,
            "output_truncated": truncated,
        }

    def _download_text(self, url: str, max_bytes: int) -> tuple[str, bool]:
        """GET a guest file-transfer URL, capped, returned as text with a truncation flag."""
        ensure_read_request("GET")
        if self._http is None:
            msg = "Session is not connected"
            raise VSphereError(msg)
        body = bytearray()
        truncated = False
        response = self._http.send(self._http.build_request("GET", url), stream=True)
        try:
            if response.status_code != 200:  # noqa: PLR2004
                return f"(output file not readable: HTTP {response.status_code})", False
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    truncated = True
                    del body[max_bytes:]
                    break
        finally:
            response.close()
        return body.decode("utf-8", errors="replace"), truncated

    # -- events --------------------------------------------------------------

    def events(
        self,
        *,
        entity: Any = None,
        begin: datetime | None = None,
        end: datetime | None = None,
        types: Sequence[str] = (),
    ) -> list[Any]:
        """The events on an entity (or everywhere), in a window, oldest first."""
        criteria = vim.event.EventFilterSpec()
        if entity is not None:
            criteria.entity = vim.event.EventFilterSpec.ByEntity(entity=entity, recursion="self")
        if begin or end:
            criteria.time = vim.event.EventFilterSpec.ByTime(beginTime=begin, endTime=end)
        if types:
            criteria.eventTypeId = list(types)
        found = self.content.eventManager.QueryEvents(criteria) or []
        return sorted(found, key=lambda event: event.createdTime)

    # -- performance ---------------------------------------------------------

    def counters(self) -> dict[str, Any]:
        """Every performance counter by `group.name.rollup`, read once per session."""
        if self._counters is None:
            self._counters = {
                f"{counter.groupInfo.key}.{counter.nameInfo.key}.{counter.rollupType}": counter
                for counter in self.content.perfManager.perfCounter
            }
        return self._counters

    def perf(
        self,
        entities: Sequence[Any],
        counter_names: Sequence[str],
        *,
        begin: datetime,
        end: datetime,
        instance: str = "*",
    ) -> tuple[dict[str, dict[str, PerfSeries]], list[str]]:
        """Samples for counters on entities, keyed by moref then counter name.

        Realtime (20 s) samples when the window is inside the last hour, the
        first historical rollup otherwise. Counter names this vCenter does not
        have come back in the second element instead of failing the read.
        """
        known = self.counters()
        # Dedupe while keeping order: a caller may pass a counter in two groups
        # (cpu.usagemhz is in both the VM and host sets), and naming it twice in
        # one QuerySpec is wrong.
        requested = list(dict.fromkeys(counter_names))
        wanted = [name for name in requested if name in known]
        unknown = [name for name in requested if name not in known]
        if not wanted or not entities:
            return {}, unknown
        now = self.now()
        interval = REALTIME_INTERVAL_SECONDS if now - begin <= REALTIME_SPAN else HISTORICAL_INTERVAL_SECONDS
        by_key = {known[name].key: name for name in wanted}
        specs = [
            vim.PerformanceManager.QuerySpec(
                entity=entity,
                metricId=[
                    vim.PerformanceManager.MetricId(counterId=known[name].key, instance=instance)
                    for name in wanted
                ],
                intervalId=interval,
                startTime=begin,
                endTime=end,
                format="normal",
            )
            for entity in entities
        ]
        batch = (
            REALTIME_ENTITIES_PER_QUERY
            if interval == REALTIME_INTERVAL_SECONDS
            else max(1, HISTORICAL_METRICS_PER_QUERY // len(wanted))
        )
        metrics = []
        for start in range(0, len(specs), batch):
            metrics.extend(self.content.perfManager.QueryPerf(specs[start : start + batch]) or [])
        results: dict[str, dict[str, PerfSeries]] = {}
        for metric in metrics:
            stamps = [as_utc(sample.timestamp) for sample in metric.sampleInfo or []]
            per_counter = results.setdefault(metric.entity._moId, {})  # noqa: SLF001
            for value in metric.value or []:
                name = by_key.get(value.id.counterId)
                if name is None:
                    continue
                series = per_counter.setdefault(
                    name,
                    PerfSeries(
                        counter=name,
                        unit=known[name].unitInfo.key,
                        interval_seconds=interval,
                    ),
                )
                series.samples[value.id.instance or ""] = [
                    (stamp, float(sample))
                    for stamp, sample in zip(stamps, value.value or [], strict=False)
                    if sample is not None and sample >= 0
                ]
        return results, unknown

    # -- host logs -----------------------------------------------------------

    def host_log(self, host: Any, key: str, lines: int) -> dict[str, Any]:
        """The last `lines` of a host log (`vmkernel`, `hostd`, `vpxa`, ...)."""
        manager = self.content.diagnosticManager
        try:
            # Without a start line, the answer is just the log's length in lineEnd.
            header = manager.BrowseDiagnosticLog(host=host, key=key)
            last = header.lineEnd
            start = max(1, last - lines + 1)
            body = manager.BrowseDiagnosticLog(host=host, key=key, start=start, lines=lines)
        except vim.fault.NotAuthenticated:
            raise  # let run() reconnect and retry, rather than hiding it as "no log"
        except (vmodl.fault.NotSupported, vmodl.MethodFault, vmodl.RuntimeFault) as fault:
            descriptions = []
            with contextlib.suppress(Exception):
                descriptions = [item.key for item in manager.QueryDescriptions(host=host)]
            return {
                "available": False,
                "reason": f"{type(fault).__name__}: {getattr(fault, 'msg', '') or fault}",
                "keys_offered": descriptions,
            }
        return {
            "available": True,
            "line_start": body.lineStart,
            "line_end": body.lineEnd,
            "lines": list(body.lineText or []),
        }

    # -- datastore files and the console --------------------------------------

    def list_folder(self, datastore: Any, folder: str, patterns: Sequence[str]) -> list[dict[str, Any]]:
        """The files in a datastore folder matching `patterns`, with sizes and times."""
        details = vim.host.DatastoreBrowser.FileInfo.Details(fileSize=True, modification=True, fileType=True)
        spec = vim.host.DatastoreBrowser.SearchSpec(matchPattern=list(patterns), details=details)
        task = datastore.browser.SearchDatastore_Task(folder, spec)
        deadline = time.monotonic() + self.settings.timeout_seconds
        while task.info.state in ("queued", "running"):
            if time.monotonic() > deadline:
                msg = f"Listing {folder} did not finish in time"
                raise VSphereError(msg)
            time.sleep(TASK_POLL_SECONDS)
        info = task.info
        if info.state != "success":
            fault = info.error
            if isinstance(fault, vim.fault.FileNotFound):
                return []
            msg = f"Listing {folder} failed: {getattr(fault, 'msg', fault)}"
            raise VSphereError(msg)
        return [
            {
                "name": item.path,
                "size": getattr(item, "fileSize", None),
                "modified": as_utc(item.modification) if getattr(item, "modification", None) else None,
            }
            for item in (info.result.file or [])
        ]

    def _get_request(
        self, path: str, params: dict[str, str], headers: dict[str, str] | None = None
    ) -> httpx.Request:
        """A GET on this vCenter's HTTPS endpoints, carrying the SOAP session."""
        ensure_read_request("GET")
        _ = self.content
        if self._http is None or self._stub is None:
            msg = "Session is not connected"
            raise VSphereError(msg)
        url = f"https://{self.vcenter.host}:{self.vcenter.port}{path}"
        return self._http.build_request(
            "GET",
            url,
            params=params,
            headers={"Cookie": session_cookie(self._stub.cookie), **(headers or {})},
        )

    def read_datastore_file(self, datacenter: str, path: str, max_bytes: int) -> DatastoreFile:
        """The end of a datastore file, at most `max_bytes` of it, over HTTPS GET."""
        datastore, inside = parse_datastore_path(path)
        # Ask for only the last `max_bytes` with a suffix Range. A vCenter that
        # honors it answers 206 with the tail; one that ignores it answers 200
        # with the whole file, which the stream below caps and tails itself.
        request = self._get_request(
            "/folder/" + quote(inside),
            {"dcPath": datacenter, "dsName": datastore},
            headers={"Range": f"bytes=-{max_bytes}"},
        )
        assert self._http is not None  # noqa: S101 - set by _get_request
        tail: collections.deque[bytes] = collections.deque()
        kept = 0
        total = 0
        capped = False
        ceiling = max(self.settings.max_download_bytes, max_bytes)
        response = self._http.send(request, stream=True)
        try:
            if response.is_redirect:
                # vCenter can redirect /folder (e.g. to the host holding the datastore).
                # Not followed: it would leave this origin, and the cookie with it.
                return DatastoreFile(path, "", None, truncated=False, status=response.status_code)
            if response.status_code not in (200, 206):
                return DatastoreFile(path, "", None, truncated=False, status=response.status_code)
            ranged = response.status_code == 206  # noqa: PLR2004
            declared = _declared_size(response, ranged=ranged)
            for chunk in response.iter_bytes():
                total += len(chunk)
                tail.append(chunk)
                kept += len(chunk)
                while kept - len(tail[0]) >= max_bytes:
                    kept -= len(tail.popleft())
                if not ranged and total >= ceiling:
                    capped = True
                    break
        finally:
            response.close()
        data = b"".join(tail)
        if capped:
            # We streamed the ceiling from the front and vCenter ignored Range, so
            # we never reached the end: the tail we hold is not the file's end.
            size = declared if declared is not None else total
            return DatastoreFile(path, "", size, truncated=True, status=416)
        truncated = len(data) > max_bytes or (ranged and bool(declared) and declared > len(data))
        if len(data) > max_bytes:
            data = data[-max_bytes:]
        if truncated:
            # Start on a whole line rather than mid-line.
            newline = data.find(b"\n")
            if newline >= 0:
                data = data[newline + 1 :]
        size = declared if declared is not None else total
        return DatastoreFile(path, data.decode("utf-8", errors="replace"), size, truncated, 200)

    def screenshot(self, moref: str) -> tuple[int, bytes, str | None]:
        """The console as vCenter renders it, over the read-only `/screen` endpoint.

        Never `CreateScreenshot_Task`: that writes a PNG into the VM's folder.
        """
        request = self._get_request("/screen", {"id": moref})
        assert self._http is not None  # noqa: S101 - set by _get_request
        response = self._http.send(request, stream=True)
        try:
            if response.status_code != 200:  # noqa: PLR2004
                # A redirect (is_redirect) is not followed: it would leave this origin.
                return response.status_code, b"", response.headers.get("content-type")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > self.settings.max_screenshot_bytes:
                    msg = "Screenshot larger than VSPHERE_MAX_SCREENSHOT_BYTES"
                    raise VSphereError(msg)
            return 200, bytes(body), response.headers.get("content-type")
        finally:
            response.close()


def _rows(objects: Iterable[Any]) -> list[dict[str, Any]]:
    rows = []
    for item in objects or []:
        row: dict[str, Any] = {"_ref": item.obj, "moref": item.obj._moId}  # noqa: SLF001
        for prop in item.propSet or []:
            row[prop.name] = prop.val
        missing = [missing.path for missing in (item.missingSet or [])]
        if missing:
            row["_missing"] = missing
        rows.append(row)
    return rows


def _not_retried(name: str, why: str) -> VSphereError:
    """The error for work that must not be repeated, when its session broke under it."""
    msg = (
        f"vCenter {name}: {why} during work that is not repeated automatically (a guest command); "
        "it may or may not have run. The session has been re-opened; check before running it again"
    )
    return VSphereError(msg)


def as_utc(value: datetime) -> datetime:
    """A vSphere timestamp as an aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class VCenterPool:
    """The configured vCenters, each with a lazy session, a limit and a deadline."""

    def __init__(self, settings: Settings) -> None:
        """Create no session until a vCenter is first read."""
        self.settings = settings
        self._sessions: dict[str, VCenterSession] = {}
        self._limits: dict[str, asyncio.Semaphore] = {}

    def names(self) -> list[str]:
        """The configured vCenters, by the name tools use."""
        return [vcenter.name for vcenter in self.settings.vcenters]

    def resolve(self, spelling: str) -> str:
        """The configured name for any spelling an upstream system used."""
        return self.settings.vcenter(spelling).name

    def session(self, name: str) -> VCenterSession:
        """The session object for a vCenter (not necessarily connected yet)."""
        if name not in self._sessions:
            self._sessions[name] = VCenterSession(self.settings.vcenter(name), self.settings)
            self._limits[name] = asyncio.Semaphore(self.settings.max_concurrent_per_vcenter)
        return self._sessions[name]

    async def run(
        self,
        name: str,
        work: Callable[[VCenterSession], T],
        *,
        retry: bool = True,
        timeout_seconds: float | None = None,
    ) -> T:
        """Run one blocking read against a vCenter, bounded, with one re-login or reconnect.

        `retry=False` is for work that must not run twice (a guest command): a
        dropped session is still re-opened for the next call, but the work is not
        repeated, and the error says it may or may not have run.
        """
        session = self.session(name)
        deadline = timeout_seconds or self.settings.timeout_seconds
        async with self._limits[name]:
            await self._bounded(session.connect)
            generation = session.generation
            try:
                return await self._bounded(lambda: work(session), deadline)
            except vim.fault.NotAuthenticated:
                # The session expired. Reconnect (a no-op if a sibling call already
                # did, so we never log its new session out), then retry once.
                await self._bounded(lambda: session.reconnect(generation))
                if not retry:
                    raise _not_retried(name, "the session expired") from None
                return await self._bounded(lambda: work(session), deadline)
            except (ssl.SSLError, ConnectionError, HTTPException) as dropped:
                # A dropped or reset connection — under load often the vCenter at
                # its connection or session limit. Reconnect and retry once; if it
                # happens again, say so plainly rather than as a bare socket error.
                if not retry:
                    with contextlib.suppress(Exception):
                        await self._bounded(lambda: session.reconnect(generation))
                    raise _not_retried(
                        name, f"the connection dropped ({type(dropped).__name__})"
                    ) from dropped
                try:
                    await self._bounded(lambda: session.reconnect(generation))
                    return await self._bounded(lambda: work(session), deadline)
                except (ssl.SSLError, ConnectionError, HTTPException) as again:
                    msg = (
                        f"vCenter {name} dropped the connection twice ({type(again).__name__}: {again}). "
                        "Under load this is often the vCenter at its connection or session limit; "
                        "check_vcenters reports its session count, and vROps has its session history."
                    )
                    raise VSphereError(msg) from again

    async def _bounded(self, work: Callable[[], T], timeout_seconds: float | None = None) -> T:
        deadline = timeout_seconds or self.settings.timeout_seconds
        try:
            return await asyncio.wait_for(asyncio.to_thread(work), timeout=deadline)
        except TimeoutError as error:
            msg = f"vCenter read exceeded VSPHERE_TIMEOUT_SECONDS ({deadline:g}s)"
            raise VSphereError(msg) from error

    def methods_seen(self) -> set[str]:
        """Every vSphere method any session has sent."""
        seen: set[str] = set()
        for session in self._sessions.values():
            seen |= session.methods_seen
        return seen

    def close(self) -> None:
        """Log every session out."""
        for session in self._sessions.values():
            session.close()
        self._sessions.clear()
