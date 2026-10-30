---
name: vm-incident
description: Diagnose why VMs on a vSphere fleet are stuck or unreachable and name the cause with evidence for and against. Use when monitoring or an orchestrator reports a VMware Tools error, a VM is stuck on first boot or after a reboot, hangs mid-run, is slow to come up, waits on a VM question, or is blocked by a virtual device (a disconnected NIC, a mounted ISO); when an environment will not come up or a test hangs waiting for it; when someone asks to find stuck, hung or leftover VMs across the vCenters; or when the vCenter API itself fails with SSL EOF errors, connection resets or timeouts. Covers ESXi CPU overcommit, storage saturation, HA restarts, host failures and guest crashes, and separates a VM that is booting slowly from one that is hung. Mostly reads; it can run a diagnostic command in a guest and reboot a wedged VM to get a fresh boot record.
---

# VM incident

This skill takes you from a symptom (a VMware Tools error, a stuck VM, a
failing vCenter) to a named cause with the evidence for and against it. You
follow the ladder in `core/ladder.md`, look up what you find in
`core/causes.md`, and end with the verdict in `core/verdict.md`. If the
evidence does not support a cause, you write what is missing and ask a person
(**stop and ask**).

Read this file first. Load the other files when a step names them.

## Identity: vCenter and moref

VMs here are short-lived (minutes to a day), and the next environment reuses
their names. A VM is identified by its **vCenter and moref** (`vc-04` /
`vm-2231`). A VM name only identifies a VM inside its environment folder.
Carry the vCenter and moref from the first tool call to the last.

## Where the evidence is

| Source | What it holds | How you reach it |
| --- | --- | --- |
| Your orchestrator or monitoring | the failing tests, the environment id, the machine names, the reboot time, the Tools error | its own tools or logs |
| The VM creator/runner logs | what it asked vCenter to do and when, its errors, how long it waited for the VM | your log store |
| vCenter | live VM state, console, `vmware.log`, serial console, events, host and datastore counters | the `vsphere-triage` server |
| vROps (optional) | days of host, cluster and datastore history; alerts | the `vrops_*` tools |
| PowerFlex (optional) | the storage backend: SDS and device health, rebuild and rebalance, per-protection-domain traffic | the `powerflex_*` tools |

Without the `vsphere-triage` tools you cannot reach vCenter: stop and ask.
Without the orchestrator or log store, say which ladder rungs you cannot
climb and work the rest.

## Where to start

| You have | Start with |
| --- | --- |
| A Tools error naming the vCenter, environment id and machine | `diagnose_vm` (ladder rung 3) |
| A question about the fleet ("anything stuck on vc-04?") | `scan`, then `explain_group` (rung 3) |
| An incident that is over, VMs possibly destroyed | `diagnose_window` (rung 3) |
| Many VMs rebooted or went unreachable at once | `cluster_events` and `recent_tasks` first (below) |
| SSL EOF errors, resets or timeouts from vCenter itself | `check_vcenters` (below) |
| "Which environments have lived too long?" | `find_old_environments`; this is cleanup, not an incident |

Climb the ladder from where you start; do not skip to the counters. A VM's
CPU and storage numbers mean nothing without the time and the symptom from
the rungs above.

## When the vCenter itself fails

SSL EOF errors, connection resets or timeouts that hit every client of a
vCenter (this server included) usually mean the vCenter is at its connection
or session limit.

1. `check_vcenters`: the open-session count, this server's last login time
   and a round-trip time per vCenter.
2. `vcenter_sessions` on the failing vCenter: sessions grouped by user,
   source IP and client, with idle counts. One client holding most sessions,
   or many idle ones from one source, is the usual leak.
3. If the failure has passed, `vcenter_history` over that window: login
   surges, failed logins and the busiest sources, in 10-minute buckets.
4. If sessions look normal but SSL or handshake errors continue,
   `check_host_time`: a host clock skewed from vCenter breaks TLS, and past
   about 300 s it breaks Kerberos/AD authentication.

If the account cannot see the global session list, `check_vcenters` says so;
use the login time and the pattern of failures across callers instead. The
fix (shedding sessions, raising the limit, fixing NTP) is for a person; the
verdict names it.

A `diagnose_vm` that keeps failing with dropped connections is the same
problem seen from one VM: run `check_vcenters` before trusting its result.

## When many VMs failed together

Check what happened above the VMs before diagnosing them one by one:

- `cluster_events`: vSphere HA restarts and VM-monitoring resets, failed
  hosts, isolated hosts, lost host connections, failed failovers and
  migration waves over a window. It names the failed host and the hosts the
  VMs were restarted onto. VMs that HA restarted after a host failure were
  rebooted on purpose: judge them from that restart, not as separate hangs.
- `recent_tasks`: what someone or an automation did in the window, e.g. a
  storage vMotion wave onto one datastore, a mass reconfigure, a snapshot
  consolidation.
- `get_host_health` on a shared host: its CPU, storage and hardware sensors.
  A failed power supply, fan or DIMM stalls every VM on the host and shows in
  none of their guest evidence.

## Tools that act on a VM

Seven tools change a VM or run code in it: `run_in_guest`, `reboot_guest`,
`hard_reset`, `check_ems`, `investigate_windows_boot`,
`investigate_linux_boot` and `read_crash_dump`. Use them only when the
read-only evidence leaves a gap that matters to the verdict, and record in the
verdict what you ran. They need VMware Tools running in the guest (except
`hard_reset`) and, for the guest-command ones, guest credentials.

**`run_in_guest`** runs one command in the guest OS and returns its output and
exit code. Use it for a question only the guest can answer: is it responsive,
what does a service or a file say. Keep the command a diagnostic that changes
nothing. A responsive guest on a starved host is still starved, so this never
replaces the host and storage checks.

**Rebooting to get a fresh boot record.** A wedged VM often has to reboot
before it writes a new `vmware.log` boot timeline, serial-console output and,
on Windows, the bugcheck its next boot records. In this order:

1. `reboot_guest`: a clean restart through Tools. Needs Tools running.
2. `hard_reset`: a power-cycle without asking the guest. It works on a fully
   hung VM, but in-flight writes, an unwritten crash dump and the hung state
   itself are lost. Use it only when Tools is down or `reboot_guest` did not
   bring the VM back. If the current state is evidence (a pending question, a
   dump being written), capture the console, serial console and events first.

Both power tools need the VM's name with its moref, and refuse a VM that is
powered off; a powered-off VM is powered on by your orchestrator or in
vCenter. After the reboot, read `get_boot_timeline` and `read_serial_console`
again. A reboot is a diagnostic step, not a fix: on a starved host or a
saturated datastore the VM will stall again on the way up.

**Reading the guest's own boot records.** Once the VM is up with Tools
running:

- Windows: `investigate_windows_boot` reads the event log (the last bugcheck,
  unclean shutdowns, service and driver start timeouts, slow-boot components,
  crash dumps, Startup Repair and update logs). `core/windows-boot.md` has the
  steps. If it finds a bugcheck, `read_crash_dump` decodes the newest
  minidump's header for the four bugcheck parameters.
- Linux: `investigate_linux_boot` reads `dmesg`, `systemd-analyze` and the
  journal for the current and the previous boot. After a reboot the hang is in
  the previous boot, which is only kept when the journal is persistent; the
  result says when it was not available.

**When the serial console has no output**, run `check_ems`. It says whether
the VM has a serial port writing to a file, whether output has appeared, and
on Windows whether EMS is enabled in the BCD, and how to enable it. Put that in
the verdict so the next incident has the serial console.

## Name the missing sources

When a better source exists but is not configured or not reachable, say so in
the verdict: what it is, what it would have shown, and how to enable it.
`diagnose_vm`, `check_vcenters`, `vcenter_history` and the guest investigations
(`investigate_windows_boot`, `investigate_linux_boot`, `read_crash_dump`) return
an `evidence_gaps` list to carry over. The common ones:

| Missing | What you cannot see | How to enable |
| --- | --- | --- |
| vROps | history: whether a spike is new or nightly, a failure that has cleared | `VSPHERE_VROPS_URL`, `_USERNAME`, `_PASSWORD` |
| Serial console / EMS | the guest's own boot messages while it is hung | the `check_ems` result |
| Guest credentials, or Tools down | the event log, the BCD, `dmesg` and the journal | `VSPHERE_GUEST_USERNAME` / `_PASSWORD`; a reboot may bring Tools back |
| PowerFlex | a backend rebuild or a hot protection domain behind a slow PowerFlex datastore | `VSPHERE_POWERFLEX_URL`, `_USERNAME`, `_PASSWORD` |

With PowerFlex configured, read `powerflex_health` (failures, rebuild,
rebalance) and `powerflex_protection_domains` (a domain carrying most of the
IOPS), and map a slow datastore to its volume with `powerflex_find_volume`.
When you already know a protection domain is in trouble, `powerflex_affected_vms`
lists the datastores on its volumes and the VMs on them, split into suffering
and not.

## Files

| Step | File |
| --- | --- |
| The ladder, rung by rung | `core/ladder.md` |
| Each state and cause, and what rules it out | `core/causes.md` |
| Checking that a correlation is a cause | `core/correlation.md` |
| The Windows boot investigation | `core/windows-boot.md` |
| The verdict format | `core/verdict.md` |
| Terms | `glossary.md` |
| Worked examples | `examples/cpu-overcommit.md`, `examples/storage-boot-storm.md` |

## Rules

1. **Identify VMs by vCenter and moref.** Never look a VM up by name outside
   its environment folder. A VM that no longer exists is reported as
   *destroyed*; that is the answer, not a reason to try another VM.
2. **Count before you explain.** Before explaining one stuck VM, find how many
   are stuck like it and what they share (`explain_group`, or the environment
   section of `diagnose_vm`). 29 of 33 VMs on one datastore within six minutes
   is a cause; one VM is not enough to say.
3. **Check shared infrastructure before the guest.** Read the host and the
   storage before blaming the guest. The two most common causes here are ESXi
   CPU overcommit and storage saturation.
4. **Check the healthy neighbours.** Before blaming a host, datastore or base
   disk, check whether healthy VMs share it. If they do, that argues against
   it. `diagnose_vm` and `explain_group` report this.
5. **Starved is not hung.** A VM using CPU with a changing console is booting
   slowly; the Tools error is then the orchestrator's timeout. `core/causes.md`
   shows how to tell. Say which one in the verdict.
6. **A shared timestamp is not a cause.** For each claim, give the evidence,
   the competing explanation and the one check that separates them
   (`core/correlation.md`).
7. **Missing data is a gap, not a clean result.** "No events in the window",
   "counters not kept", "console endpoint 404", "vROps not configured",
   `healthy: null` and "VM destroyed" all mean the tool could not see. Record
   them under Gaps.
8. **Clocks differ.** The orchestrator, the log store, each ESXi host, vCenter
   and vROps keep their own clocks. Results are in UTC with their source
   named. When two clocks disagree by more than the window you are
   correlating, say so.
9. **Act only to diagnose.** Never answer a VM question, power a VM on or off,
   reconfigure, migrate or delete. Use `reboot_guest` / `hard_reset` only to
   get a fresh boot record, as described above, never as the fix. Any other
   action the evidence calls for goes in the verdict for a person.

## Finishing

Write the headings in `core/verdict.md`, each with `none` when empty: symptom,
identity, cause with evidence for and against, causes ruled out, gaps, and the
next check or the action for a person. Do not name a cause the data does not
support.

The tool names, result fields and thresholds here are those of the server in
this repository; its README is the reference. If a result differs from what
this skill describes, the server is right; say the skill is out of date.
