"""Reading `vmware.log` and a serial console file: how far a boot got, and what stopped it.

`vmware.log` is the VMX's log: the hypervisor process that runs the VM, seeing
the virtual hardware from the outside. It does not contain the guest kernel's
own messages. What it does contain are the marks a boot leaves on the virtual
hardware (firmware, the first disk writes, paravirtual drivers announcing
themselves, Tools), and from those a timeline says how far the guest got.

The patterns below are deliberately broad and are heuristics: they were written
from VMware's documented log shapes, not from this fleet's logs, and phase 0
replaces them with the lines a real hang leaves. Every match is returned with
its line, so a reader judges the line, not the label.

A serial console file is the guest's own words: Windows Emergency Management
Services (EMS) or a Linux kernel console sent to a virtual serial port that
writes to a file. When a VM has one, stop codes and kernel errors are read from
it; when it does not, that is said and nothing else changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# ESXi 7 and later: `2026-10-29T20:13:05.123Z In(05) vmx - message`
NEW_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<level>[A-Z][a-z])\(\d+\)\s+(?P<thread>\S+)\s+-?\s*(?P<message>.*)$"
)
# ESXi 6.x: `2026-10-29T20:13:05.123Z| vmx| I125: message`
OLD_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\|\s*"
    r"(?P<thread>[^|]+?)\s*\|\s*(?P<level>[A-Z])\d*:\s?(?P<message>.*)$"
)
LEVELS = {
    "In": "info",
    "I": "info",
    "Wa": "warning",
    "W": "warning",
    "Er": "error",
    "E": "error",
    "Cr": "critical",
    "A": "critical",
    "No": "notice",
    "Db": "debug",
    "Vb": "verbose",
}

# Boot progress, in order. A boot that reached a later stage got past the earlier ones.
STAGES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "power_on_or_reset",
        "the VM was powered on or reset",
        re.compile(
            r"(?i)(powering on|transitioned vmx/execstate/val to poweredon|vmx_poweron|"
            r"resetting (the )?(vm|virtual machine)|guest[- ]initiated reset|reset request|"
            r"vmx_reset|soft reset|requested a reset)"
        ),
    ),
    (
        "firmware",
        "the firmware (BIOS or EFI) ran",
        re.compile(r"(?i)\b(bios|efi|uefi|nvram|boot manager|boot ?order|boot device)\b"),
    ),
    (
        "guest_disk_io",
        "the bootloader or kernel read and wrote the disk",
        re.compile(r"(?i)(first write on|hbacommon:)"),
    ),
    (
        "guest_drivers",
        "the guest kernel loaded its virtual-hardware drivers",
        re.compile(
            r"(?i)(vmxnet3 user|vmxnet3.*driver|pvscsi|svga.*(guest|resolution|enabl|width)|"
            r"guest display topology|e1000.*driver)"
        ),
    ),
    (
        "tools",
        "VMware Tools started talking to the host",
        # Only Tools actually coming up, not the GuestRpc channel teardown or the
        # guestinfo config dump that a reset also logs, which would otherwise mark
        # a boot that never reached Tools as having reached it.
        re.compile(
            r"(?i)(tools (are )?running|toolssetversion|tools: changing running status to .?(1|running)|"
            r"guest operations agent|vmtoolsd)"
        ),
    ),
)
STAGE_ORDER = {name: index for index, (name, _, _) in enumerate(STAGES)}

# Things that happen during a boot rather than marking progress through it.
ANNOTATIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "fault",
        re.compile(
            r"(?i)(triple fault|monitor panic|vmm panic|unrecoverable|vmx panic|core dump|"
            r"msg_post: error|bug ?check|guest.*crash)"
        ),
    ),
    (
        "storage",
        re.compile(
            r"(?i)(scsi\d*:\s*(reset|abort)|aborted? command|\bapd\b|\bpdl\b|all paths down|"
            r"permanent device loss|lost access|i/o error|stun|checkpoint_unstun|"
            r"aiomgr.*(error|fail)|disklib.*(error|fail)|timed out)"
        ),
    ),
    ("question", re.compile(r"(?i)(msg_question|msg_hint|\bquestion\b)")),
    (
        # Tools genuinely stopping or crashing after it was up — not the routine
        # "Changing running status to 1" that every healthy boot logs, which
        # would read as flapping.
        "tools_state",
        re.compile(
            r"(?i)(tools.*(stopped (working|responding)|has stopped|not running, restarting|crashed)|"
            r"changing running status to .?0\b|tools heartbeat timeout)"
        ),
    ),
)
DEFAULT_GREP = re.compile(
    "|".join(
        f"(?:{pattern.pattern.removeprefix('(?i)')})"
        for pattern in [*(stage[2] for stage in STAGES), *(item[1] for item in ANNOTATIONS)]
    ),
    re.IGNORECASE,
)

# Windows stop codes, and the layer each usually points at. A hint, never a cause.
STOP_CODES: dict[int, tuple[str, str | None]] = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "driver"),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "driver"),
    0x24: ("NTFS_FILE_SYSTEM", "storage"),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "driver"),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "driver or memory"),
    0x77: ("KERNEL_STACK_INPAGE_ERROR", "storage: paging I/O failed"),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", "storage: paging I/O failed or timed out"),
    0x7B: ("INACCESSIBLE_BOOT_DEVICE", "storage: the boot disk was not reachable"),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "driver"),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "driver"),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "driver"),
    0xED: ("UNMOUNTABLE_BOOT_VOLUME", "storage"),
    0xEF: ("CRITICAL_PROCESS_DIED", None),
    0xF4: ("CRITICAL_OBJECT_TERMINATION", "storage: often a critical process starved of disk"),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", "CPU: a vCPU did not respond in time, typical of CPU starvation"),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "hardware"),
    0x133: ("DPC_WATCHDOG_VIOLATION", "CPU or storage: a deferred call ran too long"),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "driver"),
}
STOP_NAMES = {name: (code, hint) for code, (name, hint) in STOP_CODES.items()}
STOP_CODE = re.compile(
    r"(?i)(?:\*{3}\s*stop:?\s*|bug ?check(?: code)?[:\s]+(?:was:?\s*)?|stop code[:\s]+)"
    r"(0x[0-9a-f]{1,8})"
)
STOP_NAME = re.compile(r"\b(" + "|".join(sorted(STOP_NAMES)) + r")\b")

EMS_MARK = re.compile(
    r"(?i)(sac>|special administration console|computer is booting, sac started|"
    r"\bems\b|emergency management services)"
)
# EMS prints this line at the start of each boot, so the text after its last
# occurrence is the current boot — used to keep a stop code from an earlier
# crash in the same (appended) serial file out of this boot's reading.
EMS_BOOT_BANNER = re.compile(r"(?i)computer is booting, sac started")
LINUX_MARKS: tuple[tuple[str, str | None, re.Pattern[str]], ...] = (
    ("kernel_panic", None, re.compile(r"(?i)kernel panic")),
    (
        "soft_lockup",
        "CPU: a vCPU was starved or stuck",
        re.compile(r"(?i)(soft lockup|rcu_?\w* self-detected stall|rcu.*stall)"),
    ),
    (
        "hung_task",
        "storage or CPU: a task waited too long",
        re.compile(r"(?i)blocked for more than \d+ seconds"),
    ),
    (
        "device_timeout",
        "storage: a device did not answer",
        re.compile(r"(?i)(timed out waiting for|i/o error|blk_update_request|buffer i/o error)"),
    ),
    (
        "emergency",
        "the boot dropped to an emergency shell",
        re.compile(r"(?i)(emergency mode|dracut.*(timeout|emergency|could not boot))"),
    ),
    (
        "filesystem",
        "storage: the filesystem reported errors",
        re.compile(r"(?i)(ext4-fs error|xfs.*(error|corrupt))"),
    ),
    ("oops", None, re.compile(r"(?i)(\boops\b|call trace)")),
)


@dataclass
class LogLine:
    """One parsed log line. `time` is None for a continuation or an unparsed line."""

    number: int
    time: datetime | None
    level: str | None
    thread: str | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        """The line as a result shows it."""
        return {
            "line": self.number,
            "time": self.time,
            "level": self.level,
            "thread": self.thread,
            "message": self.message,
        }


def parse_time(text: str) -> datetime | None:
    """An ISO timestamp from a log line, as UTC."""
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def parse_lines(text: str, first_number: int = 1) -> list[LogLine]:
    """Every line of a `vmware.log`, in either the ESXi 6 or the ESXi 7+ format."""
    lines = []
    for offset, raw in enumerate(text.splitlines()):
        match = NEW_LINE.match(raw) or OLD_LINE.match(raw)
        if match is None:
            lines.append(LogLine(first_number + offset, None, None, None, raw))
            continue
        lines.append(
            LogLine(
                number=first_number + offset,
                time=parse_time(match["ts"]),
                level=LEVELS.get(match["level"], match["level"]),
                thread=match["thread"].strip(),
                message=match["message"],
            )
        )
    return lines


def grep(
    lines: list[LogLine],
    pattern: str | None,
    *,
    since: datetime | None = None,
    limit: int,
) -> tuple[list[LogLine], int]:
    """Lines matching `pattern` (the boot-relevant default when None), newest `limit`.

    Returns the lines kept and how many matched in all.
    """
    expression = DEFAULT_GREP if pattern is None else re.compile(pattern, re.IGNORECASE)
    matched = [
        line
        for line in lines
        if expression.search(line.message) and (since is None or line.time is None or line.time >= since)
    ]
    return matched[-limit:], len(matched)


def boot_timeline(lines: list[LogLine], *, max_examples: int = 3) -> dict[str, Any]:
    """How far the last boot in this log got, and what happened along the way."""
    start_index = None
    for index, line in enumerate(lines):
        if STAGES[0][2].search(line.message):
            start_index = index
    if start_index is None:
        return {
            "boot_found": False,
            "note": "no power-on or reset found in the part of vmware.log read",
            "stages": [],
            "last_stage": None,
            "annotations": {},
        }
    boot = lines[start_index:]
    stages = []
    reached = set()
    for name, meaning, pattern in STAGES:
        for line in boot:
            if pattern.search(line.message):
                stages.append(
                    {
                        "stage": name,
                        "meaning": meaning,
                        "first_seen": line.time,
                        "line": line.as_dict(),
                    }
                )
                reached.add(name)
                break
    last = max(reached, key=STAGE_ORDER.__getitem__)
    missing = [name for name, _, _ in STAGES if STAGE_ORDER[name] > STAGE_ORDER[last]]
    annotations: dict[str, Any] = {}
    for name, pattern in ANNOTATIONS:
        hits = [line for line in boot if pattern.search(line.message)]
        if hits:
            annotations[name] = {
                "count": len(hits),
                "first": hits[0].time,
                "last": hits[-1].time,
                "examples": [line.as_dict() for line in hits[:max_examples]],
            }
    last_time = next((line.time for line in reversed(boot) if line.time), None)
    last_stage_time = next(item["first_seen"] for item in stages if item["stage"] == last)
    silent_after = None
    if last_time and last_stage_time:
        silent_after = (last_time - last_stage_time).total_seconds()
    return {
        "boot_found": True,
        "boot_started": boot[0].time,
        "stages": sorted(stages, key=lambda item: STAGE_ORDER[item["stage"]]),
        "last_stage": last,
        "not_reached": missing,
        "last_log_line_time": last_time,
        "seconds_from_last_stage_to_end_of_log": silent_after,
        "annotations": annotations,
        "heuristic": (
            "stages are matched by pattern against the VMX's log, not read from the "
            "guest; check the quoted lines"
        ),
    }


def stop_codes(text: str) -> list[dict[str, Any]]:
    """Windows stop codes found in text (a serial log or OCR of the console)."""
    found: dict[int | str, dict[str, Any]] = {}
    for match in STOP_CODE.finditer(text):
        code = int(match.group(1), 16)
        name, hint = STOP_CODES.get(code, (None, None))
        found[code] = {"code": f"0x{code:08X}", "name": name, "points_at": hint}
    for match in STOP_NAME.finditer(text):
        name = match.group(1)
        code, hint = STOP_NAMES[name]
        if code not in found:
            found[code] = {"code": f"0x{code:08X}", "name": name, "points_at": hint}
    return list(found.values())


def read_serial(text: str, *, tail_lines: int) -> dict[str, Any]:
    """What a serial console file says: EMS or kernel output, stop codes, errors."""
    lines = text.splitlines()
    ems = bool(EMS_MARK.search(text))
    linux = []
    for name, hint, pattern in LINUX_MARKS:
        hits = [line for line in lines if pattern.search(line)]
        if hits:
            linux.append({"kind": name, "points_at": hint, "count": len(hits), "examples": hits[:3]})
    # A serial file is appended across reboots, so a stop code earlier in it may
    # be from a previous boot. When EMS marked the boots, read stop codes only
    # from the current boot (after the last banner); otherwise read the whole
    # file and say the code's boot is not certain.
    banners = [match.start() for match in EMS_BOOT_BANNER.finditer(text)]
    current = text[banners[-1] :] if banners else text
    codes = stop_codes(current)
    return {
        "bytes": len(text.encode()),
        "lines": len(lines),
        "empty": not text.strip(),
        "ems_output_seen": ems,
        "windows_stop_codes": codes,
        "stop_codes_scoped_to_current_boot": bool(banners),
        "linux_findings": linux,
        "tail": lines[-tail_lines:],
    }
