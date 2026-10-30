"""Can we read the guest's own boot words — and if not, exactly why, and how to fix it.

The serial console is the only channel that carries a guest's own errors while it
is too wedged to reach VMware Tools: on Windows that is Emergency Management
Services (EMS), on Linux a kernel console. Missing it is the single biggest hole
in a boot investigation, so this answers the capability question in full rather
than just failing to find output:

1. **Hardware** — does the VM have a virtual serial port backed by a datastore
   file? Read from the VM's devices; no guest needed. Without it, EMS has
   nowhere to write, full stop.
2. **Output** — has EMS/console output actually landed in that file? Read from
   the serial file; proof it is enabled and working.
3. **Configuration** — when VMware Tools and guest credentials are available, is
   EMS actually turned on in the guest's BCD? `bcdedit /enum {current}` carries
   the `ems` flag and `{emssettings}` the port/baud. This closes the ambiguous
   middle case: a serial port exists but no output has appeared — is EMS off, or
   has the guest simply not emitted yet?

The verdict names whether the guest's boot words are readable, and when they are
not, why and how to turn them on. The BCD parsing is pure and tested here; the
guest read is `check_ems`.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from vsphere_triage import capabilities
from vsphere_triage.diagnose import locate, read_serial_files
from vsphere_triage.guestexec import encode_powershell

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

_EMS_FLAG = re.compile(r"(?im)^\s*ems\s+(\S+)\s*$")
# bcdedit translates Yes/No with the guest's display language.
_YES = frozenset({"yes", "ja", "oui", "si", "sí", "sim", "да", "是", "はい", "tak", "igen", "ano"})
# Locale-independent marks that the dump is a real boot entry (the loader path).
_BOOT_ENTRY = re.compile(r"(?i)\\windows\\system32\\winload")
_EMS_PORT = re.compile(r"(?im)^\s*emsport\s+(\S+)")
_EMS_BAUD = re.compile(r"(?im)^\s*emsbaudrate\s+(\d+)")
_ACCESS_DENIED = re.compile(r"(?i)access is denied|requires elevation|elevated")


def bcd_probe_powershell() -> str:
    """A PowerShell script that dumps the boot entry and EMS settings as JSON.

    It changes nothing: it only runs `bcdedit /enum`, never `/set` (like every
    guest probe it writes its output to a guest temp file and deletes it). bcdedit needs an
    elevated token to read the store, so a non-admin run returns "Access is
    denied", which the parser reports as "unconfirmed" rather than "off".
    """
    return (
        "$out = @{};"
        "try { $out.current = (bcdedit /enum '{current}' | Out-String) }"
        ' catch { $out.current = "ERROR: $_" };'
        "try { $out.emssettings = (bcdedit /enum '{emssettings}' | Out-String) }"
        ' catch { $out.emssettings = "ERROR: $_" };'
        "$out | ConvertTo-Json -Compress"
    )


def _extract_json(output: str) -> dict[str, Any]:
    """The first JSON object in a command's output, or {} if there is none."""
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        parsed = json.loads(output[start : end + 1])
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse_bcd_output(output: str) -> dict[str, Any]:
    """Read the `ems` flag and EMS port/baud out of a bcdedit dump.

    `ems_enabled` is True/False when the boot entry says so, and None when it
    could not be read (bcdedit needs elevation, or the output was unusable) —
    None means "unconfirmed", never "off".
    """
    parsed = _extract_json(output)
    current = str(parsed.get("current", "")) if parsed else output
    settings = str(parsed.get("emssettings", "")) if parsed else output
    flag = _EMS_FLAG.search(current)
    access_denied = bool(_ACCESS_DENIED.search(current))
    if flag is not None:
        enabled: bool | None = flag.group(1).lower() in _YES
    elif not access_denied and _BOOT_ENTRY.search(current):
        # The entry was read and has no `ems` line: bcdedit omits a setting never
        # set, and EMS is off by default. That is "off", not "unconfirmed".
        enabled = False
    else:
        enabled = None
    port = _EMS_PORT.search(settings)
    baud = _EMS_BAUD.search(settings)
    return {
        "ems_enabled": enabled,
        "emsport": port.group(1) if port else None,
        "emsbaudrate": int(baud.group(1)) if baud else None,
        "access_denied": access_denied,
        "read": enabled is not None or port is not None,
    }


def _verdict(  # noqa: PLR0911 - one capability, each outcome beside it
    vm_os: str,
    *,
    has_serial_to_file: bool,
    ems_output_seen: bool,
    bcd: dict[str, Any] | None,
    gap: dict[str, Any] | None,
) -> dict[str, Any]:
    """Whether the guest's boot words are readable, and when not, why and how."""
    how = gap["how_to_enable"] if gap else None
    why_it_matters = gap["impact"] if gap else None
    if ems_output_seen:
        return {
            "available": True,
            "state": "working",
            "why": "the serial console file already holds the guest's output, so it is enabled and working",
        }
    if not has_serial_to_file:
        return {
            "available": False,
            "state": "no_serial_port",
            "why": "the VM has no virtual serial port writing to a file, so the console output cannot land",
            "how_to_enable": how,
            "why_it_matters": why_it_matters,
        }
    if vm_os != "windows":
        return {
            "available": True,
            "state": "serial_port_present",
            "why": (
                "a serial port to a file is present; EMS is a Windows feature, so on this guest confirm "
                "the kernel console is directed to the port (no bcdedit to check)"
            ),
        }
    if bcd is None:
        return {
            "available": None,
            "state": "unconfirmed_no_guest_access",
            "why": (
                "a serial port is present but no output has appeared yet; whether EMS is enabled cannot "
                "be confirmed without VMware Tools and guest credentials to read the BCD"
            ),
            "how_to_enable": (
                "provide guest access so bcdedit can be read, or enable EMS (see the gap's how_to_enable)"
            ),
        }
    if bcd.get("access_denied"):
        return {
            "available": None,
            "state": "unconfirmed_bcdedit_denied",
            "why": "bcdedit could not read the store (it needs an elevated account), so EMS state is unknown",
            "how_to_enable": "run with an elevated guest account to read {current}/{emssettings}",
        }
    if bcd.get("ems_enabled") is None:
        return {
            "available": None,
            "state": "unconfirmed_unreadable",
            "why": (
                "the bcdedit output could not be read (exit code "
                f"{bcd.get('exit_code')}, timed out: {bcd.get('timed_out')}), so EMS state is unknown"
            ),
            "how_to_enable": "rerun check_ems, or run `bcdedit /enum {current}` with run_in_guest",
        }
    if bcd.get("ems_enabled") is True:
        return {
            "available": True,
            "state": "configured_not_yet_emitted",
            "why": "the serial port is present and EMS is enabled in the BCD; output should appear next boot",
        }
    return {
        "available": False,
        "state": "serial_port_but_ems_off",
        "why": "a serial port is present but EMS is off in the guest's BCD, so nothing is written to it",
        "how_to_enable": (
            "enable EMS in the guest: `bcdedit /ems on` and "
            "`bcdedit /emssettings EMSPORT:1 EMSBAUDRATE:115200`"
        ),
        "why_it_matters": why_it_matters,
    }


async def check_ems(
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
    """Report whether a VM's serial console (EMS on Windows) can carry its boot words."""
    user = username or settings.guest_username
    secret = password or settings.guest_password

    # Found first, in a read that may be retried; the guest command below never is.
    def find(session: VCenterSession) -> tuple[dict[str, Any], dict[str, Any]]:
        located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref, strict=True)
        serial = read_serial_files(session, located["vm"]) if located["found"] else {}
        return located, serial

    # The VM and its serial files are reads, so they may be retried; only the guest
    # command below never is.
    pre_located, serial = await pool.run(name, find)

    def work(session: VCenterSession) -> dict[str, Any]:
        located = pre_located
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        ems_output_seen = any(
            file.get("ems_output_seen") for file in serial.get("files", []) if file.get("available")
        )
        bcd: dict[str, Any] | None = None
        if vm.os_family == "windows" and vm.powered_on and vm.tools_up and user and secret:
            result = session.run_in_guest(
                vm.moref,
                windows=True,
                command=encode_powershell(bcd_probe_powershell()),
                username=user,
                password=secret,
                timeout_seconds=settings.guest_exec_timeout_seconds,
                max_output_bytes=settings.guest_exec_max_output_bytes,
            )
            bcd = parse_bcd_output(result.get("output", "")) | {
                "exit_code": result.get("exit_code"),
                "timed_out": result.get("timed_out"),
            }
        gap = capabilities.serial_console_gap(vm)
        verdict = _verdict(
            vm.os_family,
            has_serial_to_file=bool(vm.serial_files),
            ems_output_seen=ems_output_seen,
            bcd=bcd,
            gap=gap,
        )
        return {
            "found": True,
            "vm": vm.identity(),
            "verdict": verdict,
            "hardware": {"serial_port_to_file": bool(vm.serial_files), "serial_files": vm.serial_files},
            "ems_output_seen": ems_output_seen,
            "bcd": bcd,
            "guest_checked": bcd is not None,
        }

    # A guest command inside: never repeated on a dropped session (a second process,
    # a second temp file), and given the guest timeout on top of the reads.
    return await pool.run(
        name,
        work,
        retry=False,
        timeout_seconds=settings.timeout_seconds + settings.guest_exec_timeout_seconds,
    )
