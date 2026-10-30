"""Run a command inside a guest — the one capability that is NOT read-only.

Everything else this server does only reads from vSphere. This tool executes a
caller-supplied command in the guest OS through VMware Tools guest operations,
and the user has explicitly allowed that for diagnostics. It therefore goes
through the session's raw (unguarded) stub, not the read-only stub the rest of
the server is bound to, and it is the only path that can change a VM.

It needs two things the read-only tools do not: VMware Tools running in the
guest, and guest-OS credentials (per call, or the configured defaults). Output
is captured by redirecting the command to a temp file in the guest, downloading
it, and deleting it — so a small, temporary write to the guest filesystem is
part of running it.

The command-shaping is pure and tested here; the SOAP dance is
`VCenterSession.run_in_guest`.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from vsphere_triage.diagnose import locate

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

WINDOWS_SHELL = r"C:\Windows\System32\cmd.exe"
LINUX_SHELL = "/bin/sh"


def guest_temp_path(token: str, *, windows: bool) -> str:
    """Where the command's output is redirected in the guest, by OS."""
    if windows:
        return rf"C:\Windows\Temp\vsphere-triage-{token}.txt"
    return f"/tmp/vsphere-triage-{token}.txt"  # noqa: S108 - a path inside the guest, not a host temp file


def guest_program_spec(command: str, out_path: str, *, windows: bool) -> tuple[str, str]:
    """The interpreter and arguments to run `command` and capture stdout+stderr to `out_path`.

    The whole command is captured, not only its last part: on Linux the shell's
    own output is redirected first (`exec >`), so `a; b`, `a || b` and `a && b`
    all land in the file; on Windows the command is grouped in parentheses.
    The command is handed to the guest's shell as-is; a command containing the
    shell's own quote character (or, on Windows, an unbalanced parenthesis) can
    break the wrapping, which is a known limit of running an arbitrary string
    rather than an argv.
    """
    if windows:
        return WINDOWS_SHELL, f'/c ({command}) > "{out_path}" 2>&1'
    return LINUX_SHELL, f"-c \"exec > '{out_path}' 2>&1; {command}\""


def encode_powershell(script: str) -> str:
    """A cmd.exe-safe command that runs `script` in PowerShell.

    PowerShell's `-EncodedCommand` takes base64 of UTF-16LE, so the whole script
    — braces, quotes, newlines and all — travels as one token with nothing for
    the guest's shell to mis-parse. This is how the Windows investigations (EMS
    BCD state, the boot picture) run multi-statement scripts through the
    single-string guest-exec channel without quote breakage.
    """
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"


def encode_shell(script: str) -> str:
    """A shell-safe command that runs a multi-line `script` under /bin/sh.

    The script is base64-encoded and piped through `base64 -d | sh`, so the whole
    thing — pipes, quotes, greps — travels as one token with nothing for the
    guest's shell wrapper to mis-parse, the Linux counterpart of
    `encode_powershell`.
    """
    encoded = base64.b64encode(script.encode()).decode("ascii")
    return f"echo {encoded}|base64 -d|sh"


def rewrite_transfer_url(url: str, host: str) -> str:
    """Resolve the guest file-transfer URL, whose host vCenter returns as `*` ('where you connected')."""
    return url.replace("://*", f"://{host}", 1) if "://*" in url else url


async def run_in_guest(  # noqa: PLR0913 - one guest command, its target and its credentials
    pool: VCenterPool,
    settings: Settings,
    name: str,
    *,
    moref: str | None,
    env_id: str | None,
    vm_name: str | None,
    command: str,
    username: str | None,
    password: str | None,
) -> dict[str, Any]:
    """Locate the VM, check it can take a command, and run it in the guest."""
    user = username or settings.guest_username
    secret = password or settings.guest_password
    if not user or not secret:
        msg = (
            "no guest credentials: pass username and password, or configure VSPHERE_GUEST_USERNAME and "
            "VSPHERE_GUEST_PASSWORD. run_in_guest executes a command inside the guest and cannot do so "
            "without an account in it"
        )
        raise ValueError(msg)

    def check(session: VCenterSession) -> dict[str, Any]:
        """Find the VM and whether it can take a command: reads only, so safe to retry."""
        located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref)
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if not vm.powered_on:
            return {
                "found": True,
                "ran": False,
                "reason": "the VM is not powered on, so nothing can run in it",
            }
        if not vm.tools_up:
            return {
                "found": True,
                "ran": False,
                "reason": (
                    "VMware Tools is not running in this guest, so guest operations are unavailable; "
                    f"Tools status is {vm.tools_running!r}. The read-only tools (console, serial, boot log) "
                    "are how a guest with no Tools is seen"
                ),
            }
        return {"found": True, "vm": vm}

    checked = await pool.run(name, check)
    if "vm" not in checked:
        return checked
    vm = checked["vm"]

    def execute(session: VCenterSession) -> dict[str, Any]:
        result = session.run_in_guest(
            vm.moref,
            windows=vm.os_family == "windows",
            command=command,
            username=user,
            password=secret,
            timeout_seconds=settings.guest_exec_timeout_seconds,
            max_output_bytes=settings.guest_exec_max_output_bytes,
        )
        return {"found": True, "ran": True, "vm": vm.identity(), **result}

    # Never repeated on a dropped session: the command may already have run. The
    # deadline covers the command's own timeout on top of the transfer around it.
    return await pool.run(
        name,
        execute,
        retry=False,
        timeout_seconds=settings.timeout_seconds + settings.guest_exec_timeout_seconds,
    )
