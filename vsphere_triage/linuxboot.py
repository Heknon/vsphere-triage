"""Build the picture of a Linux boot from the guest's own logs.

The mirror of the Windows boot investigation. `vmware.log`, the console and the
serial console show a Linux boot from outside; the kernel's and systemd's own
account is inside the guest, reachable once VMware Tools is up. So, as on
Windows: if the VM is off or hung, reboot it (reboot_guest, else hard_reset) and
let it come up, then read, in one pass:

- **`dmesg`** — kernel panics, soft-lockups / RCU stalls, hung-task warnings
  ("blocked for more than N seconds"), device I/O timeouts, filesystem errors,
  and a drop to the dracut/emergency shell. Classified with the same patterns
  the serial-console reader uses, and mapped to the layer each points at.
- **`systemd-analyze blame` / `critical-chain`** — which units made the boot
  slow, and the critical path through them.
- **`journalctl -b`** — the current boot's warnings and errors.
- **`journalctl -b -1`** — the *previous* boot's: after a reboot of a hung VM
  the current boot is the healthy one, and the hang is in the boot before it.
  Only there when the journal is persistent; said when it is not.

dmesg and the journal may be restricted to root/adm, so a non-privileged run can
come back thin; that is reported, not hidden. The script-building and the
parsing are pure and tested here; the guest read is `investigate_linux_boot`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vsphere_triage import capabilities, vmlog
from vsphere_triage.diagnose import locate
from vsphere_triage.guestexec import encode_shell, probe_failed

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

# Section markers the probe prints, so the combined output parses back apart.
_MARKERS = ("LAST_BOOT", "BLAME", "CRITICAL", "DMESG_LINES", "DMESG", "JOURNAL", "BOOTS", "PREVIOUS")


def boot_probe_shell() -> str:
    """A /bin/sh script that prints the Linux boot evidence in marked sections."""
    patterns = "panic|oops|call trace|hung_task|blocked for more than|soft lockup|rcu.*stall|"
    patterns += "i/o error|blk_update_request|ext4-fs error|xfs.*(error|corrupt)|timed out|"
    patterns += "dracut|emergency mode"
    return (
        "echo ===LAST_BOOT===; (uptime -s 2>/dev/null || who -b 2>/dev/null);"
        "echo ===BLAME===; systemd-analyze blame 2>/dev/null | head -n 15;"
        "echo ===CRITICAL===; systemd-analyze critical-chain 2>/dev/null | head -n 20;"
        # The unfiltered line count tells "dmesg was readable and nothing matched"
        # from "dmesg was restricted" — the filtered section alone cannot.
        "echo ===DMESG_LINES===; dmesg 2>/dev/null | wc -l;"
        f"echo ===DMESG===; dmesg 2>/dev/null | grep -iE '{patterns}' | tail -n 40;"
        "echo ===JOURNAL===; journalctl -b -p warning -o short-iso --no-pager 2>/dev/null | tail -n 60;"
        # How many boots the journal holds: one means it is not persistent, and the
        # boot before a reboot (the one that hung) is gone.
        "echo ===BOOTS===; journalctl --list-boots --no-pager 2>/dev/null | wc -l;"
        "echo ===PREVIOUS===; journalctl -b -1 -p warning -o short-iso --no-pager 2>/dev/null | tail -n 60;"
        "echo ===END==="
    )


def _split_sections(output: str) -> dict[str, list[str]]:
    """The probe output split on its `===MARKER===` lines into {marker: lines}."""
    sections: dict[str, list[str]] = {marker: [] for marker in _MARKERS}
    current: str | None = None
    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("===") and stripped.endswith("==="):
            label = stripped.strip("=")
            current = label if label in sections else None
            continue
        if current and line:
            sections[current].append(line)
    return sections


def _slow_units(blame_lines: list[str]) -> list[dict[str, str]]:
    """The units systemd-analyze blame lists, as {time, unit} (already slowest-first)."""
    units = []
    for line in blame_lines:
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].strip():  # noqa: PLR2004 - "<time> <unit>"
            units.append({"time": parts[0], "unit": parts[1].strip()})
    return units


def summarize_linux_boot(output: str) -> dict[str, Any]:
    """Turn the raw probe output into a boot picture: what the kernel and systemd say."""
    sections = _split_sections(output)
    kernel_findings: list[dict[str, Any]] = []
    scan_lines = sections["DMESG"] + sections["JOURNAL"]
    for name, hint, pattern in vmlog.LINUX_MARKS:
        hits = [line for line in scan_lines if pattern.search(line)]
        if hits:
            kernel_findings.append(
                {"kind": name, "points_at": hint, "count": len(hits), "examples": hits[:3]}
            )
    previous_findings: list[dict[str, Any]] = []
    for name, hint, pattern in vmlog.LINUX_MARKS:
        hits = [line for line in sections["PREVIOUS"] if pattern.search(line)]
        if hits:
            previous_findings.append(
                {"kind": name, "points_at": hint, "count": len(hits), "examples": hits[:3]}
            )
    boots_text = " ".join(sections["BOOTS"]).strip()
    boots = int(boots_text) if boots_text.isdigit() else None
    slow = _slow_units(sections["BLAME"])
    picture: list[str] = []
    for finding in previous_findings:
        layer = f" — {finding['points_at']}" if finding["points_at"] else ""
        picture.append(f"previous boot: {finding['count']}x {finding['kind']}{layer}")
    for finding in kernel_findings:
        layer = f" — {finding['points_at']}" if finding["points_at"] else ""
        picture.append(f"current boot: {finding['count']}x {finding['kind']}{layer}")
    previous_read = bool(sections["PREVIOUS"]) or (boots is not None and boots > 1)
    if not previous_read:
        picture.append(
            "the previous boot's journal is not available (the journal is not persistent, or was not "
            "readable): if this VM was rebooted after hanging, the boot that hung was NOT read — "
            "the serial console and vmware.log are the record of it"
        )
    if slow:
        picture.append(f"slowest unit at boot: {slow[0]['unit']} ({slow[0]['time']})")
    dmesg_text = " ".join(sections["DMESG_LINES"]).strip()
    dmesg_lines = int(dmesg_text) if dmesg_text.isdigit() else None
    # Thin only when nothing could be read at all: a readable dmesg with no fault
    # lines is a clean result, not a restricted one.
    thin = not dmesg_lines and not sections["DMESG"] and not sections["JOURNAL"]
    if thin:
        picture.append(
            "dmesg and the journal came back empty — likely restricted to root/adm; run as a "
            "privileged account for the kernel's own words"
        )
    return {
        "last_boot": " ".join(sections["LAST_BOOT"]) or None,
        "picture": picture or ["no kernel faults found in what could be read"],
        "kernel_findings": kernel_findings,
        "previous_boot_findings": previous_findings,
        "previous_boot_read": previous_read,
        "boots_in_journal": boots,
        "slow_units": slow,
        "critical_chain": sections["CRITICAL"],
        "restricted": thin,
    }


async def investigate_linux_boot(
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
    """Read a Linux guest's own boot logs and build the picture of why it went wrong."""
    user = username or settings.guest_username
    secret = password or settings.guest_password

    # Found first, in a read that may be retried; the guest command below never is.
    pre_located = await pool.run(
        name,
        lambda session: locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref, strict=True),
    )

    def work(session: VCenterSession) -> dict[str, Any]:  # noqa: PLR0911 - each reason it cannot look
        located = pre_located
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if not vm.powered_on:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "the VM is powered off, so its boot logs cannot be read. Power it on first (from your "
                    "orchestrator or vCenter: this server has no power-on tool, and reboot_guest / "
                    "hard_reset only act on a running VM), let it come up, then investigate"
                ),
            }
        if vm.os_family == "windows":
            return {
                "found": True,
                "investigated": False,
                "reason": "this is a Windows guest; use investigate_windows_boot",
            }
        if not vm.tools_up:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "VMware Tools is not running, so the guest's logs are unreachable; if the VM is "
                    "wedged, reboot_guest or hard_reset may bring Tools back. Meanwhile the serial "
                    "console and console screenshot are the only view"
                ),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        if not user or not secret:
            return {
                "found": True,
                "investigated": False,
                "reason": (
                    "no guest credentials: pass username and password, or configure "
                    "VSPHERE_GUEST_USERNAME / VSPHERE_GUEST_PASSWORD, to read the guest's boot logs"
                ),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        result = session.run_in_guest(
            vm.moref,
            windows=False,
            command=encode_shell(boot_probe_shell()),
            username=user,
            password=secret,
            timeout_seconds=settings.guest_exec_timeout_seconds,
            max_output_bytes=settings.guest_exec_max_output_bytes,
        )
        failed = probe_failed(result)
        if failed:
            return {
                "found": True,
                "investigated": False,
                "vm": vm.identity(),
                "reason": failed + "; nothing about the guest's boot was read",
                "exit_code": result.get("exit_code"),
                "evidence_gaps": capabilities.evidence_gaps(settings, vm),
            }
        return {
            "found": True,
            "investigated": True,
            "vm": vm.identity(),
            "boot": summarize_linux_boot(result.get("output", "")),
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
