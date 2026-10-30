r"""Decode a Windows crash dump's header: the bugcheck code and its parameters.

`investigate_windows_boot` reads the bugcheck from the event log (WER 1001). The
dump file itself carries more — the four bugcheck parameters, which the event
usually omits — and this reads them straight from the kernel minidump's header
(`DUMP_HEADER64`), where the code sits at offset 0x38 and the four parameters at
0x40/0x48/0x50/0x58. That needs no debugger and no symbols, so it is air-gap
safe; only the newest minidump in `C:\Windows\Minidump` is read (small), not the
multi-gigabyte `MEMORY.DMP`.

What this does NOT do is name the faulting driver — that is `!analyze -v` in
WinDbg against Microsoft's symbol server, which does not fit a pure-Python,
air-gapped tool. So this is the code and its parameters, decoded to the layer
the code points at; the driver stays WinDbg's job.

The probe-building and the decode are pure and tested; the guest read is
`read_crash_dump`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vsphere_triage import capabilities, vmlog
from vsphere_triage.diagnose import locate
from vsphere_triage.emscheck import _extract_json
from vsphere_triage.guestexec import encode_powershell, probe_failed

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession


def dump_probe_powershell() -> str:
    r"""A PowerShell script that reads the newest minidump's header and emits JSON.

    Reads only the first 96 bytes (the DUMP_HEADER64 fields we need), so it is
    cheap and never pulls the dump itself. 64-bit kernel dumps only (signature
    `PAGEDU64`); a 32-bit dump is reported with its signature so the reader knows.
    """
    return (
        "$md='C:\\Windows\\Minidump';"
        # Missing folder, unreadable folder (non-admin) and no dump are three answers.
        'if(-not (Test-Path $md)){\'{"found":false,"folder":false}\';exit};'
        "try{$f=Get-ChildItem $md -Filter *.dmp -ErrorAction Stop|"
        "Sort-Object LastWriteTime -Descending|Select-Object -First 1}"
        'catch{\'{"found":false,"denied":true}\';exit};'
        "if(-not $f){'{\"found\":false}';exit};"
        "$buf=New-Object byte[] 96;"
        # A dump that cannot be opened (locked, denied) is said so, never read as zeros.
        "try{$fs=[System.IO.File]::OpenRead($f.FullName);[void]$fs.Read($buf,0,96);$fs.Close()}"
        'catch{\'{"found":false,"unreadable":"\'+$f.Name+\'"}\';exit};'
        "$sig=[System.Text.Encoding]::ASCII.GetString($buf,0,8);"
        "$code=[BitConverter]::ToUInt32($buf,0x38);"
        "$p=@([BitConverter]::ToUInt64($buf,0x40),[BitConverter]::ToUInt64($buf,0x48),"
        "[BitConverter]::ToUInt64($buf,0x50),[BitConverter]::ToUInt64($buf,0x58));"
        "@{found=$true;name=$f.Name;time=$f.LastWriteTime.ToUniversalTime().ToString('o');"
        "signature=$sig;code=$code;params=$p}|ConvertTo-Json -Compress"
    )


def decode_dump(parsed: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 - one answer per way the read can go
    """Decode the probe JSON: bugcheck code to its name and layer, parameters to hex. Pure."""
    if not parsed:
        return {
            "found": False,
            "reason": "the guest probe returned nothing readable; not evidence of no dump",
        }
    if parsed.get("denied"):
        return {
            "found": False,
            "reason": (
                r"C:\Windows\Minidump could not be read (it needs an elevated account); "
                "not evidence of no dump"
            ),
        }
    if parsed.get("unreadable"):
        return {
            "found": False,
            "reason": f"the newest minidump ({parsed['unreadable']}) could not be opened (locked or denied)",
        }
    if parsed.get("folder") is False:
        return {
            "found": False,
            "reason": r"C:\Windows\Minidump does not exist: no small dump was ever written (check that "
            r"crash dumps are configured, and C:\Windows\MEMORY.DMP)",
        }
    if not parsed.get("found"):
        return {"found": False, "reason": r"no minidump found in C:\Windows\Minidump"}
    if parsed.get("signature") not in (None, "PAGEDU64"):
        # The offsets read are DUMP_HEADER64's; a 32-bit (PAGEDUMP) header puts the
        # bugcheck elsewhere, so decoding it would name a wrong stop code.
        return {
            "found": True,
            "dump": parsed.get("name"),
            "signature": parsed.get("signature"),
            "bugcheck": None,
            "note": "not a 64-bit kernel dump (PAGEDU64); its header is not decoded — open it in WinDbg",
        }
    code = parsed.get("code")
    name, points_at = (None, None)
    if isinstance(code, int):
        name, points_at = vmlog.STOP_CODES.get(code, (None, None))
    params = parsed.get("params") or []
    return {
        "found": True,
        "dump": parsed.get("name"),
        # When the dump was written: an old dump is an old crash, not this incident's.
        "written": parsed.get("time"),
        "signature": parsed.get("signature"),
        "bugcheck": {
            "code": f"0x{code:08X}" if isinstance(code, int) else None,
            "name": name,
            "points_at": points_at,
        },
        "parameters": [f"0x{value:016X}" if isinstance(value, int) else str(value) for value in params],
        "note": (
            "decoded from the dump header (bugcheck code and its 4 parameters); naming the faulting "
            "driver needs WinDbg `!analyze -v` with symbols, which this air-gapped tool does not do"
        ),
    }


async def read_crash_dump(
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
    """Read the newest Windows minidump's header and decode its bugcheck."""
    user = username or settings.guest_username
    secret = password or settings.guest_password

    # Found first, in a read that may be retried; the guest command below never is.
    pre_located = await pool.run(
        name,
        lambda session: locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref, strict=True),
    )

    def work(session: VCenterSession) -> dict[str, Any]:
        located = pre_located
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if vm.os_family != "windows":
            return {
                "found": True,
                "read": False,
                "reason": "crash dumps are a Windows concept; this guest is not Windows",
            }
        if not vm.powered_on or not vm.tools_up or not user or not secret:
            return {
                "found": True,
                "read": False,
                "reason": (
                    "needs the VM powered on with VMware Tools running and guest credentials; reboot it "
                    "first if it is hung (power it on from your orchestrator if it is off), and pass or "
                    "configure VSPHERE_GUEST_USERNAME/PASSWORD"
                ),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        result = session.run_in_guest(
            vm.moref,
            windows=True,
            command=encode_powershell(dump_probe_powershell()),
            username=user,
            password=secret,
            timeout_seconds=settings.guest_exec_timeout_seconds,
            max_output_bytes=settings.guest_exec_max_output_bytes,
        )
        failed = probe_failed(result)
        if failed:
            return {"found": True, "read": False, "vm": vm.identity(), "reason": failed}
        decoded = decode_dump(_extract_json(result.get("output", "")))
        # `found` is the VM's; whether a dump was found is `dump_found`.
        return {
            "found": True,
            "read": True,
            "vm": vm.identity(),
            "dump_found": decoded.pop("found"),
            **decoded,
        }

    # A guest command inside: never repeated on a dropped session (a second process,
    # a second temp file), and given the guest timeout on top of the reads.
    return await pool.run(
        name,
        work,
        retry=False,
        timeout_seconds=settings.timeout_seconds + settings.guest_exec_timeout_seconds,
    )
