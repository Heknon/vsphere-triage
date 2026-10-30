r"""Build the picture of a Windows boot from the guest's own records.

`vmware.log` shows a boot from the outside; the console and serial console show
what the screen and EMS carried. None of them is the Windows event log, which is
where Windows itself records *why* a boot went wrong — and it is only reachable
once the guest is up enough for VMware Tools. So the flow is: if the VM is off or
wedged, reboot it (reboot_guest, then hard_reset) and let it come back; then read
these, in one pass, through the guest:

- **WER `1001`** (System log) — the bugcheck code the last crash recorded on the
  *next* boot. This survives a reboot loop, so a BSOD never captured live is
  still named here.
- **Kernel-Power `41`** / **EventLog `6008`** — the system went down without a
  clean shutdown; the reboot was not graceful.
- **Service Control Manager `7000`/`7009`/`7011`/`7026`** — a service or
  boot-start driver timed out. For Windows, "the kernel timed out" is very often
  really a service-start timeout, and this is where it is named.
- **Diagnostics-Performance `100`-`103`** — boot-performance monitoring: the
  overall boot time and the specific app / driver / service that delayed it.
- **crash dumps** (`MEMORY.DMP`, newest `Minidump\*.dmp`), **`ntbtlog.txt`**
  (per-driver load list), **`SrtTrail.txt`** (Startup Repair's own diagnosis),
  and the update **Panther** log for "Working on updates" hangs.

The script changes nothing in Windows — only `Get-WinEvent`, `Get-Item`,
`Get-Content`, `Test-Path` — but it runs through guest exec, so like
`run_in_guest` it writes its output to a temp file in the guest and deletes it.
The script-building and the parsing are pure and tested here; the guest read
is `investigate_windows_boot`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vsphere_triage import capabilities, vmlog
from vsphere_triage.diagnose import locate
from vsphere_triage.guestexec import encode_powershell, probe_failed

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

# How many of each event kind to bring back: enough to see a pattern, bounded so
# the single guest-exec download stays small.
PER_KIND = 5


def boot_probe_powershell() -> str:
    """A PowerShell script that gathers the Windows boot evidence into one JSON object.

    Every query is wrapped so a missing log or an access error becomes an empty
    list rather than failing the whole probe, and messages are trimmed so the
    download stays small.
    """
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "function ev($h){ try { Get-WinEvent -FilterHashtable $h -MaxEvents "
        f"{PER_KIND} |"
        " ForEach-Object { @{ time=$_.TimeCreated.ToUniversalTime().ToString('o');"
        " id=$_.Id; provider=$_.ProviderName;"
        # Collapse whitespace first, then cut the collapsed text by its own length:
        # cutting it by the original length throws on any message with a double space
        # or CRLF (WER 1001 has both), and the catch would drop the whole event kind.
        " message=$($m=([string]$_.Message -replace '\\s+',' ');"
        " $m.Substring(0,[Math]::Min(300,$m.Length))) } } }"
        " catch { @() } }"
        "$o=[ordered]@{};"
        "$o.last_boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');"
        "$o.bugchecks=@(ev @{LogName='System';"
        "ProviderName='Microsoft-Windows-WER-SystemErrorReporting';Id=1001});"
        "$o.kernel_power=@(ev @{LogName='System';Id=41});"
        "$o.dirty_shutdown=@(ev @{LogName='System';ProviderName='EventLog';Id=6008});"
        "$o.service_timeouts=@(ev @{LogName='System';"
        "ProviderName='Service Control Manager';Id=7000,7009,7011,7026});"
        "$o.boot_performance=@(ev @{"
        "LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100,101,102,103});"
        "$md='C:\\Windows\\Minidump';"
        "$o.newest_minidump=(Get-ChildItem $md -Filter *.dmp | Sort-Object LastWriteTime -Descending |"
        " Select-Object -First 1 | ForEach-Object { @{ name=$_.Name;"
        " time=$_.LastWriteTime.ToUniversalTime().ToString('o') } });"
        "$o.memory_dmp=(Test-Path 'C:\\Windows\\MEMORY.DMP');"
        "$o.ntbtlog=(Test-Path 'C:\\Windows\\ntbtlog.txt');"
        "$srt='C:\\Windows\\System32\\LogFiles\\Srt\\SrtTrail.txt';"
        # $( ): `if` is a statement, so inside plain ( ) it is an error that
        # SilentlyContinue hid, and SrtTrail was never reported.
        "$o.srttrail=$(if (Test-Path $srt) { (Get-Content $srt -Tail 40 | Out-String) } else { $null });"
        "$pan='C:\\Windows\\Panther\\setupact.log';"
        "$o.panther_present=(Test-Path $pan);"
        "$o | ConvertTo-Json -Depth 5 -Compress"
    )


def _decode_bugchecks(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pull the stop code out of each WER 1001 message and name the layer it points at."""
    decoded = []
    for row in rows:
        codes = vmlog.stop_codes(str(row.get("message", "")))
        decoded.append(
            {
                "time": row.get("time"),
                "stop_codes": codes,
                "message": row.get("message"),
            }
        )
    return decoded


def summarize_windows_boot(parsed: dict[str, Any]) -> dict[str, Any]:
    """Turn the raw probe JSON into a boot picture: what Windows says went wrong."""
    bugchecks = _decode_bugchecks(parsed.get("bugchecks") or [])
    service_timeouts = parsed.get("service_timeouts") or []
    boot_perf = parsed.get("boot_performance") or []
    dirty = parsed.get("dirty_shutdown") or []
    kernel_power = parsed.get("kernel_power") or []
    picture: list[str] = []
    latest_code = next((code for row in bugchecks for code in row["stop_codes"]), None)
    if latest_code:
        layer = f" — points at {latest_code['points_at']}" if latest_code.get("points_at") else ""
        picture.append(
            f"last bugcheck {latest_code['code']}"
            + (f" {latest_code['name']}" if latest_code.get("name") else "")
            + layer
        )
    if service_timeouts:
        picture.append(
            f"{len(service_timeouts)} service/driver start timeout(s) (SCM 7009/7011) — a service, "
            "not the kernel, may be what hung the boot"
        )
    if dirty or kernel_power:
        picture.append("the system went down without a clean shutdown (Kernel-Power 41 / EventLog 6008)")
    slow = [row for row in boot_perf if row.get("id") in (101, 102, 103)]
    if slow:
        picture.append(f"{len(slow)} slow-boot component(s) named by Diagnostics-Performance (101/102/103)")
    if parsed.get("srttrail"):
        picture.append("Startup Repair ran and left SrtTrail.txt — read it for its own diagnosis")
    if parsed.get("panther_present"):
        picture.append("a Windows Update Panther log is present — a 'Working on updates' hang is possible")
    return {
        "last_boot": parsed.get("last_boot"),
        "picture": picture or ["no boot faults found in the event log window read"],
        "bugchecks": bugchecks,
        "service_timeouts": service_timeouts,
        "boot_performance": boot_perf,
        "dirty_shutdowns": dirty,
        "kernel_power": kernel_power,
        "crash_dumps": {
            "newest_minidump": parsed.get("newest_minidump"),
            "memory_dmp_present": parsed.get("memory_dmp"),
        },
        "repair_and_update": {
            "ntbtlog_present": parsed.get("ntbtlog"),
            "srttrail_tail": parsed.get("srttrail"),
            "panther_present": parsed.get("panther_present"),
        },
    }


async def investigate_windows_boot(
    pool: VCenterPool,
    settings: Settings,
    name: str,
    *,
    moref: str | None,
    env_id: str | None,
    vm_name: str | None,
    username: str | None,
    password: str | None,
) -> dict[str, Any]:
    """Read a Windows guest's own boot records and build the picture of why it went wrong."""
    user = username or settings.guest_username
    secret = password or settings.guest_password

    def work(session: VCenterSession) -> dict[str, Any]:  # noqa: PLR0911 - one guard per precondition
        located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref, strict=True)
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if not vm.powered_on:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "the VM is powered off, so its running event log cannot be read. Power it on first "
                    "(from your orchestrator or vCenter: there is no power-on tool here, and reboot_guest / "
                    "hard_reset only act on a running VM), let it come up, then investigate"
                ),
            }
        if vm.os_family != "windows":
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    f"this guest is {vm.os_family!r}, not Windows; read its serial console / dmesg instead"
                ),
            }
        if not vm.tools_up:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "VMware Tools is not running, so the guest's event log is unreachable; if the VM is "
                    "wedged, reboot_guest or hard_reset may bring Tools back. Meanwhile the serial "
                    "console (EMS) and console screenshot are the only view"
                ),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        if not user or not secret:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "no guest credentials: pass username and password, or configure "
                    "VSPHERE_GUEST_USERNAME / VSPHERE_GUEST_PASSWORD, to read the Windows event log"
                ),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        result = session.run_in_guest(
            vm.moref,
            windows=True,
            command=encode_powershell(boot_probe_powershell()),
            username=user,
            password=secret,
            timeout_seconds=settings.guest_exec_timeout_seconds,
            max_output_bytes=settings.guest_exec_max_output_bytes,
        )
        from vsphere_triage.emscheck import _extract_json  # noqa: PLC0415 - shared JSON extraction

        failed = probe_failed(result)
        if failed:
            return {
                "found": True,
                "investigated": False,
                "vm": vm.identity(),
                "reason": failed + "; nothing about the guest's boot was read",
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        parsed = _extract_json(result.get("output", ""))
        if not parsed:
            return {
                "found": True,
                "investigated": False,
                "reason": "the guest probe returned no readable JSON; see raw_output",
                "raw_output": result.get("output", "")[:2000],
                "exit_code": result.get("exit_code"),
            }
        return {
            "found": True,
            "investigated": True,
            "vm": vm.identity(),
            "boot": summarize_windows_boot(parsed),
            "evidence_gaps": capabilities.evidence_gaps(settings, vm),
        }

    # A guest command inside: never repeated on a dropped session (a second process,
    # a second temp file), and given the guest timeout on top of the reads.
    return await pool.run(
        name,
        work,
        retry=False,
        timeout_seconds=settings.timeout_seconds + settings.guest_exec_timeout_seconds,
    )
