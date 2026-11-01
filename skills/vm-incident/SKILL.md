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
| The runner (the machine calling vCenter) | its own connections, connection table, ports, CPU, proxy and path to vCenter and the hosts | your own shell over SSH, only with a person's OK (`core/runner.md`); the `vsphere-triage` server cannot reach it |
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
| Many VMs raise Tools errors at once (a creation burst, busy hosts) | `correlate_hosts` (below) |
| SSL EOF errors, resets or timeouts from vCenter itself | `check_vcenters` (below) |
| Guest file transfers (`guestFile`) fail with SSL EOFs, resets or timeouts | `check_host_tls` (below) |
| SSL EOFs or "Tools errors" from one runner while the server side looks clean | `core/runner.md` (below) |
| "Which environments have lived too long?" | `find_old_environments`; this is cleanup, not an incident |

Climb the ladder from where you start; do not skip to the counters. A VM's
CPU and storage numbers mean nothing without the time and the symptom from
the rungs above.

## When the vCenter itself fails

SSL EOF errors, connection resets or timeouts that hit every client of a
vCenter (this server included) often mean the vCenter is at its session or
connection limit, but not always. First ask **which calls fail**:

- **Guest file transfers** (`guestFile` in the error, or `run_in_guest`'s
  `output_error` says the download failed): go to *When guest file transfers
  fail* below. That download goes to the ESXi host, not to vCenter, so the
  session count does not explain it.
- **API calls to vCenter itself**: follow these steps.
- **Only one client fails** (one runner or automation host), while others of
  the same vCenter work: the runner or its path may be the cause. Clear the
  server side with the steps below, then go to *When the client may be the
  problem*.

1. `check_vcenters`: the open-session count **against the configured cap**
   (`session_limit`, read from `config.vmacore.soap.maxSessionCount`), this
   server's last login time and a round-trip time per vCenter. A count at or
   near the cap (`limit_finding`) is the answer. When no cap is set,
   `session_limit` is null and vpxd's built-in default applies; the API cannot
   read that default, so do not claim a number for it.
2. `vcenter_sessions` on the failing vCenter: sessions grouped by user,
   source IP and client, with idle counts, the cap, and every
   session/connection setting an administrator set (`connection_settings`).
   One client holding most sessions, or many idle ones from one source, is
   the usual leak. `calls_by_client` is each client's API call total over its
   open sessions. It only grows, so to see a **request rate** call
   `vcenter_sessions` twice, a minute or two apart, and divide the difference
   by the time between them (use the times of the two reads). A client
   whose rate is far above the rest, at the time of the errors, is a request
   swarm: many guest operations (each transfer is several vCenter calls) or
   tight polling. Two cautions: a session that closed between the reads takes
   its calls with it, so a client that logs in per request shows a drop or
   noise, not a rate (its login surge shows in `vcenter_history` instead); and
   the rate covers vCenter calls only, not the downloads that go to the hosts.
3. If the failure has passed, `vcenter_history` over that window: login
   surges, failed logins and the busiest sources, in 10-minute buckets.
4. If the count is well under the cap, the session limit is not the cause.
   Look at what else drops connections:
   - `vcenter_appliance_health`: memory, swap, disk and database health, the
     appliance's uptime (a recent restart dropped every connection at that
     time) and services that are up but unhealthy (vpxd, envoy, the reverse
     proxy).
   - `read_vcenter_log` (vpxd) with a `pattern` such as
     `session|connection|SSL|refused`, at the time of the failures.
   - `check_host_time`: a host clock skewed from vCenter breaks TLS, and past
     about 300 s it breaks Kerberos/AD authentication.

The reverse proxy's own connection limit and live connection count are not in
the vSphere API. On 7.0 and later Envoy owns port 443 and caps remote HTTPS
connections (2048 by default, `maxRemoteHttpsConnections` in
`/etc/vmware-rhttpproxy/config.xml`); at the cap it closes connections, which
clients see as SSL EOFs, and `/var/log/vmware/envoy/envoy.log` says "remote
https connections exceed" (Broadcom KB 344920). That fits SSL EOFs better than
the session cap, which shows as refused logins. If everything above is clean,
say Envoy is the remaining suspect and that a person must read that log on the
appliance (**stop and ask**).

Two more limits sit beside vpxd's: on 8.0 vpxd shortens session timeouts as the
count nears the cap (`config.vmacore.soap.enableSessionTimeoutPenalties`, KB
336100), so an idle count can drop on its own; and the REST API (vAPI) keeps
its own per-user session pool, separate from the SOAP count.

If the account cannot see the global session list, `check_vcenters` says so;
use the login time and the pattern of failures across callers instead. The
fix (shedding sessions, raising the limit, fixing NTP) is for a person; the
verdict names it.

A `diagnose_vm` that keeps failing with dropped connections is the same
problem seen from one VM: run `check_vcenters` before trusting its result.

## When guest file transfers fail

A guest file transfer is two steps: a call to vCenter that returns a URL, then
an HTTPS download from that URL. The URL names the **ESXi host**, so the
download never touches vCenter. This is how the API works, not a guess to
confirm. Failures here are about the host and the path to it:

1. `check_host_tls`: from where this server runs, at the address the transfer
   URL carries (through vCenter that is the host's **IP address**, not its
   name), whether 443 answers, is refused or resets, and whether the host's
   certificate is trusted, unexpired and covers that address. Every host
   failing the same way means no transfer can work from here; a few failing
   points at those hosts. `no_address_to_probe` means this server could not
   find the address at all: that host was not tested, which is not a failure.
2. `search_host_logs` (hostd by default): the matching lines on every
   connected host, counted per host. Concentrated on a few hosts points at
   those hosts (certificate, hostd load, their network); spread over most
   hosts points at what they all share (the network, the client).
3. `read_host_log` on the worst host for its full context.
4. If you suspect a swarm of transfers, measure the automation's request rate
   on vCenter: `vcenter_sessions` twice, a minute or two apart, and compare
   `calls_by_client` (see *When the vCenter itself fails*, step 2). Each
   transfer is several vCenter calls before its download, so a swarm shows as
   one client's calls racing ahead. Whether the errors scale with that rate is
   the test; throttling the automation and watching the errors fall confirms
   it.

`check_host_tls` tests from this server. The failing client may be somewhere
else with its own path. If this server cannot reach the hosts (or cannot find
their address) while the client gets as far as an SSL EOF, the two paths
differ: say so, and give the person the same handshake to run from the client
against the address in a failing URL (`openssl s_client -connect
<address>:443`). Such a URL works once, for ten minutes. If the probe is
clean but the client still fails, the client's path or the host side is left.

## When the client may be the problem

The machine calling vCenter (a runner, an automation host) can cause the same
`SSLEOFError`, resets and timeouts as the server: an idle connection dropped
by a firewall or NAT and then reused (the **first call after a pause** fails,
a retry works), a full connection table, ports or file descriptors run out, a
starved container, a proxy or an MTU problem in the path, or one pyVmomi
connection shared across threads. A runner whose own status call fails can
also report a "Tools error" on a VM whose Tools is fine: check that VM in
vCenter (`diagnose_vm` or `scan`).

The tools only clear the server side. If it is clean at the error time,
load `core/runner.md`: the signs, the read-only commands to run on the runner
over SSH (from your own shell or a paramiko script, only after a person names
the runner and its access), and the packet capture that shows who closed the
connection. Without runner-side evidence, name the runner as the remaining
suspect, not as the cause.

## When many VMs failed together

Check what happened above the VMs before diagnosing them one by one:

- `cluster_events`: vSphere HA restarts and VM-monitoring resets, failed
  hosts, isolated hosts, lost host connections, failed failovers and
  migration waves over a window. It names the failed host and the hosts the
  VMs were restarted onto. VMs that HA restarted after a host failure were
  rebooted on purpose: judge them from that restart, not as separate hangs.
- `recent_tasks`: what someone or an automation did in the window, e.g. a
  storage vMotion wave onto one datastore, a mass reconfigure, a snapshot
  consolidation, or a clone/power-on wave (mass VM creation), with the
  busiest 10 minutes of clones and of power-ons.
- `get_host_health` on a shared host: its CPU, storage and hardware sensors.
  A failed power supply, fan or DIMM stalls every VM on the host and shows in
  none of their guest evidence.

## When many VMs raise Tools errors at once

A wave of Tools errors, often with SSL errors on guest file transfers at the
same time, usually has one of three shapes. `correlate_hosts` over the window
tells them apart: per host, the VMs in Tools trouble now, the VMs created and
powered on in the window, the host's CPU demand peak, VMs not ready for guest
operations, and the hostd guest-transfer/TLS lines.

- **Tools trouble follows host load** (most of it on overcommitted hosts):
  starved guests bring Tools up late and drop its heartbeat. Confirm with
  `explain_group` on the host group, or `get_host_health` on the worst host.
- **Tools trouble follows the creation burst** (on the hosts that took the
  power-ons), with a clone/power-on wave in the task stream: mass creation is
  the load. The fix is pacing the creation, for a person to decide.
- **Transfer failures land on the same hosts** as the Tools trouble: one load
  explains both. **Transfer failures on otherwise quiet hosts**: a different
  cause for them; go to *When guest file transfers fail*.

VMs flagged `guest_ops_not_ready` run Tools but cannot take a guest command or
file transfer yet; an automation that starts one then gets a failure that
looks like a connection error. It should wait for the guest to report ready.
The Tools trouble counted is the VMs' state now: for a wave that has passed,
use `diagnose_window` over its window.

A monitoring "Tools error" can also be the monitoring's own call to vCenter
failing (an SSL EOF on the status check). If vCenter shows Tools running on a
VM the monitoring flagged, check the vCenter side (*When the vCenter itself
fails*).

## Tools that act on a VM

Seven tools change a VM or run code in it: `run_in_guest`, `reboot_guest`,
`hard_reset`, `check_ems`, `investigate_windows_boot`,
`investigate_linux_boot` and `read_crash_dump`. Use them only when the
read-only evidence leaves a gap that matters to the verdict, and record in the
verdict what you ran. `run_in_guest`, `reboot_guest`, the two
`investigate_*` tools and `read_crash_dump` need VMware Tools running in the
guest (and, except `reboot_guest`, guest credentials). `hard_reset` needs
neither. `check_ems` reads the serial port and its output file without Tools;
only its Windows BCD check needs Tools and credentials, so run it on a VM whose
Tools is down too. If none of these tools is listed, the server was started
without guest execution: record that as a gap. Each one
needs the VM's name with its moref (or the environment id with the name) and
refuses when the VM at that moref has another name: morefs repeat across
vCenters.

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

Both power tools refuse a VM that is powered off; a powered-off VM is powered on by your orchestrator or in
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
`diagnose_vm`, `check_vcenters`, `vcenter_history`, `check_datastores` and the guest investigations
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
`powerflex_affected_vms` finds the troubled protection domains itself (a rebuild
or degraded state, or most of the IOPS) and lists the datastores on their
volumes and the VMs on them, split into suffering and not. It takes no domain
to look at: if it reports none troubled, the domain you suspected did not meet
that test, which is evidence too.

## Files

| Step | File |
| --- | --- |
| The ladder, rung by rung | `core/ladder.md` |
| Each state and cause, and what rules it out | `core/causes.md` |
| Checking that a correlation is a cause | `core/correlation.md` |
| The Windows boot investigation | `core/windows-boot.md` |
| Checking the runner (the client) over SSH | `core/runner.md` |
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
