# The Windows boot investigation

`vmware.log` and the console show a Windows boot from outside. The reason it
failed (the bugcheck, the service that timed out, the driver that would not
load) is in the guest's own records, which can only be read while the guest is
running with VMware Tools up. So the steps are: get the guest up, read its
records, then interpret them.

## 1. Get the guest up

- **Powered off:** power it on from your orchestrator or in vCenter. This
  server has no power-on tool, and the two reboot tools act only on a running
  VM.
- **Hung:** reboot it.
  1. `reboot_guest` if VMware Tools still responds.
  2. `hard_reset` only if Tools is down or `reboot_guest` did not bring it
     back. It loses in-flight writes and any dump being written; capture the
     console, serial console and events first if the current state is
     evidence. It also records an unclean shutdown in the event log.

Wait until the VM is up and Tools reports running. If it never comes up, read
the boot from outside instead (`get_boot_timeline`, `read_serial_console`,
`get_vm_console`), and run `check_ems` to see whether the serial console can
carry the guest's boot messages.

## 2. Read the records

`investigate_windows_boot` runs a fixed PowerShell script in the guest (it
needs Tools and guest credentials) and returns the parsed results. The script
changes nothing in Windows; like every guest command it writes its output to a
temp file in the guest and deletes it.

| Record | What it tells you |
| --- | --- |
| **WER 1001** (bugcheck) | the stop code of the last crash, written on the next boot, so a crash in a reboot loop is still named; decoded to its layer (storage, CPU, driver) |
| **Kernel-Power 41, EventLog 6008** | the system went down without a clean shutdown; a `hard_reset` causes this too |
| **SCM 7000, 7009, 7011, 7026** | a service or boot driver failed or timed out; on Windows this is often what "the boot timed out" really is |
| **Diagnostics-Performance 100-103** | boot duration, and the application, driver or service that slowed it |
| **Crash dumps** (`MEMORY.DMP`, the newest minidump) | a dump exists; `read_crash_dump` decodes the minidump's bugcheck code and parameters |
| **ntbtlog, SrtTrail, Panther** | the driver-load log, Startup Repair's diagnosis, and the Windows Update log behind "Working on updates" |

Only events from one day before the latest boot onward count as this
incident's. Older bugchecks are returned as `older_bugchecks` and other older
events as `older_events`. If the VM was hung for more than a day before this
boot, check those too.

## 3. Interpret

- A **bugcheck with a storage layer** (`0x7A`, `0x7B`, `0xF4`) points back at
  the datastore: a saturated datastore can starve the boot disk. A **CPU
  layer** (`0x101` clock watchdog, `0x133` DPC watchdog) points at host
  overcommit. Confirm either against the host and datastore evidence before
  writing it as the cause.
- A **service timeout** (7011, 7009) means a service hung the boot, not the
  kernel. Name the service; it is a guest-software problem.
- **Slow-boot components** (101, 102, 103) name what made the boot slow.
- **No findings** means nothing was recorded in the window read. If the VM
  hung more than a day before the latest boot, read `older_events`.

Put the bugcheck or timeout and its layer in the verdict. If EMS or guest
access was not available, say so under Gaps with how to enable it.
