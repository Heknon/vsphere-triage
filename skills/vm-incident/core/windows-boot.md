# Building a Windows boot picture

`vmware.log` and the console show a Windows boot from the outside. The *why* —
the bugcheck, the service that timed out, the driver that would not load — lives
in the guest's own records, and those are reachable only once the guest is up
enough for VMware Tools. So the Windows boot investigation has an order.

## 1. Get the guest up

If the VM is powered off or wedged, you cannot read its running event log.
A powered-off VM has to be powered on from your orchestrator or vCenter (this
server has no power-on tool; both tools below act only on a running VM). A
wedged one, reboot, preferring the graceful path:

1. `reboot_guest` — if VMware Tools can still act.
2. `hard_reset` — only if Tools is down or the graceful reboot never returned.
   It is destructive (see the SKILL); if the live state is itself the evidence
   (a dump still writing, "Working on updates"), capture console/serial first.

Let it come back and Tools report running. If it will not come up at all, you
are not doing a Windows-log investigation yet — that is a boot *failure*, read
from the outside (`get_boot_timeline`, `read_serial_console`, `get_vm_console`)
and from EMS; see `check_ems` for whether EMS is even available.

## 2. Read the records in one pass

`investigate_windows_boot` runs a fixed, read-only PowerShell probe through the
guest (Tools + credentials needed) and returns a parsed picture:

| Signal | What it tells you |
| --- | --- |
| **WER 1001** (bugcheck) | the stop code the *last* crash recorded on the next boot — survives a reboot loop; decoded to its layer (storage / CPU / driver) |
| **Kernel-Power 41 / EventLog 6008** | the system went down without a clean shutdown — the reboot was not graceful |
| **SCM 7000 / 7009 / 7011 / 7026** | a service or boot-start driver timed out. On Windows this is very often what "the kernel timed out" really is |
| **Diagnostics-Performance 100-103** | boot time, and the specific app / driver / service that delayed it |
| **crash dumps** (`MEMORY.DMP`, newest minidump) | a dump exists to analyse (`!analyze -v` offline) |
| **ntbtlog / SrtTrail / Panther** | driver-load log, Startup-Repair's own diagnosis, and the "Working on updates" trail |

## 3. Read the picture

- A **bugcheck** with a storage layer (`0x7A`, `0x7B`, `0xF4`) points back at the
  shared-cause checks: a saturated datastore can starve the boot disk. A CPU
  layer (`0x101` CLOCK_WATCHDOG, `0x133` DPC_WATCHDOG) points at host overcommit.
  Do not stop at the code — confirm it against the host and datastore evidence.
- A **service timeout** (7011) means a service, not the kernel, hung the boot;
  name the service, and treat it as a guest-software problem, not infrastructure.
- **Slow-boot components** (101/102/103) answer "why was boot *slow*" by name.
- **Nothing found** is a real answer only once you confirm the window covered the
  boot in question; otherwise widen it or reboot and watch a fresh one.

Record the bugcheck/timeout and its layer in the verdict, and — per the
missing-capability standard — if EMS or guest access was unavailable, say so and
how to enable it, because the next incident will be easier to read with it.
