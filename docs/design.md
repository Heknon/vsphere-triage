# Plan: vSphere and vROps for incident diagnosis (an MCP and a skill)

Status: the MCP is built as the `vsphere_triage` package at the repo root (see
the README) and tested against two simulated vCenters in Docker; section 12 says
what was built and what was not. The `vm-incident` skill is built in `skills/vm-incident/`
(table-top evals in its `evals/`, not yet run on a live vCenter). The
PowerFlex adapter is not built yet. Section 11 lists the open questions.

## 1. What it is

Today an agent investigating a broken Sahara environment can read two of
the four layers: Sahara (the Sahara MCP) and Sims/Twix (their logs in
Elastic). When the trail reaches the VMs, a person takes over: opens the
vCenter, finds the machine, looks at the console, browses the datastore
for `vmware.log`, checks the host and the storage. This plan puts those
steps in the agent's reach:

- **`vsphere-mcp`**: an MCP server over the nine vCenters, vROps and,
  optionally, PowerFlex. **Read-only, with no exceptions**: it looks things
  up and diagnoses. It powers nothing on or off, answers no VM question,
  creates, moves, reconfigures or deletes nothing, and writes no file on
  any datastore. It is not a service that runs on its own either: it
  answers when the agent asks, like the Sahara MCP.
- **`vm-incident` skill**: the procedure from a Sahara VMware Tools error
  to a verdict, through Sims logs, vCenter, vROps and PowerFlex, with the
  causes seen so far and the evidence that separates them.

## 2. The fleet, and how a machine is found

- **Environments are short-lived.** Sims/Twix creates an environment's VMs
  on one of the nine vCenters and destroys them after 10 minutes to 24
  hours. A VM name is reused by later environments, so a name alone never
  identifies a machine.
- **The Twix environment id is the anchor.** Each environment is a folder
  on its vCenter, under a parent that groups environments. There are two
  kinds of vCenter: one kind groups them as *environments*, the other as
  *projects*. Within a kind the layout is the same on every vCenter.
  The environment's VMs are the VMs in its folder.
- **Sahara already holds the way in.** Its VMware Tools error logs carry
  the vCenter, the machine name and the environment id, somewhere in
  their extra data. From those three the MCP goes straight to the
  machine: vCenter → environment folder → VM by name inside it. Within one
  environment's folder a name is unique; across environments it is not,
  and the MCP never searches by name outside the folder.

### 2.1 Concepts, not constants

Nothing in the MCP or the skill hard-codes a folder path, a log field
name, a vCenter's kind or a naming pattern. Layouts change, and a
hard-coded path turns every inconsistency into a wrong answer or a
silent miss. Instead:

- **The MCP discovers.** `find_environment(env_id)` looks for folders
  whose name is or contains the env id, on the vCenter given or on all of
  them, and reports *what it found and where*: the full folder path, the
  parent it sits under, how many VMs it holds. One match is used; none or
  several are reported as such, with the candidates, never guessed
  between. It does not need to know whether a vCenter is the
  environments kind or the projects kind; it reports which parent the
  folder sat under, and the model can see it.
- **Config may give hints, never requirements.** An optional list of
  parent folder names to look under first makes the lookup faster; if
  the env is not found there, the MCP looks everywhere and says so.
- **The skill teaches the concepts**: an environment is a folder named by
  its Twix id, under an environments or projects parent; a VM is
  identified by its vCenter and moref, its name only inside its folder;
  the Sahara log carries the vCenter, the machine and the env id under
  some key in its extra data, so read the record and find them rather
  than expect one field name. When the data does not match the concept
  (two folders for one id, a VM outside any env folder, a log without a
  vCenter), the skill says to report the inconsistency as a finding, not
  to work around it silently.
- **Thresholds are defaults, and the raw values always come back.** A
  check that says "CPU starvation" also returns the demand and ready time
  it judged on, so the model, and the person reading, can disagree.
- **The VMs are linked clones.** Each VM's disk is a thin delta on top
  of a shared, read-only base disk (the template's or a replica's). Every
  VM cloned from one base reads that same base disk while it boots. So
  the unit that is shared, and can be the cause, is often **the base disk**,
  not only the host or the datastore: fifty clones booting at once all
  read one disk on one PowerFlex volume. The MCP reads each VM's disk
  chain (the delta and its parents) from its configuration, read-only, and
  groups by base disk the same way it groups by host and datastore. The
  base disk's identity is discovered from the chain, never assumed from a
  template name.
- **Once found, the key is `(vcenter, moref)`**, with `instanceUuid` and
  `config.createDate` alongside. Every later call uses that key. If the
  VM has since been destroyed, the tool says *destroyed* and does not fall
  back to another VM with the same name.
- **A destroyed environment leaves less behind.** `vmware.log`, the
  console and the live state go with the VM. vCenter's events and tasks
  (for its retention period), host and datastore counters, vROps and
  PowerFlex history remain. The tools say which of these a diagnosis
  rested on.

## 3. The incident it is built around

The recurring symptom: Sahara reports VMware Tools errors after a reboot,
because the VM did not come back in time. Two causes found behind it so
far:

- **ESXi CPU overcommitted**: hosts at around 120% CPU demand. A booting
  VM waits for CPU constantly (ready time), so a 60-second boot takes ten
  minutes and Tools start after Sims or Sahara gave up. Often the VM is
  starved, not hung, and comes up later on its own.
- **PowerFlex saturated**: very high IOPS on the storage. A booting guest
  reads its disk hard; with device latency in the hundreds of
  milliseconds the bootloader and kernel stall, and a long stall looks
  like a hang on the console.

The flow, once this exists:

1. **Sahara**: the VMware Tools error log gives vCenter `vc-04`, machine
   `web-01`, environment `env-8812`, and the time.
2. **`diagnose_vm(vcenter="vc-04", env_id="env-8812", vm_name="web-01")`**,
   one call:
   - *machine*: powered on, booted 14 minutes ago, Tools not running,
     heartbeat gray, no pending question, CPU at 100% of one vCPU;
   - *console*: two captures 10 s apart, not black, changing (the guest is
     doing something);
   - *`vmware.log`*: the reset at 02:13:05, firmware handover, guest
     activity since;
   - *host `esx-31`*: CPU demand 118% of capacity for the last 40 minutes;
     this VM's ready time 38% per vCPU during boot;
   - *datastore*: latency normal;
   - *environment*: 4 of the 6 VMs in `env-8812` are in the same state,
     all on `esx-31` and `esx-32`, both above 110% demand; the 2 healthy
     ones are on `esx-40`.
   - *finding*: CPU starvation on `esx-31` and `esx-32`; the VM is booting
     slowly, not hung.
3. **vROps**: the cluster's demand over the past week: was this a spike
   or the normal state of the cluster?
4. **Verdict** (from the skill): the Tools error is a timeout on a VM
   starved of CPU on two overcommitted hosts; the environment and its
   template are not the cause, because its VMs on another host booted
   normally. Next check: why those hosts are above capacity (placement,
   or what else runs on them).

For the PowerFlex case, the same call reports the datastore's device
latency high in the boot window and, with the PowerFlex adapter, the
storage pool behind it and its IOPS.

## 4. The layers

| Layer | Owner | Agent access today | Holds |
| --- | --- | --- | --- |
| Sahara | application | Sahara MCP | the Tools error with vCenter, machine name and env id; the time of each step |
| Sims / Twix | infrastructure | logs in Elastic | what Sims asked the vCenter and when, its errors, timeouts |
| vCenter ×9 | bare metal | **none** | the environment folder and its VMs, live state, console, `vmware.log`, events and tasks, host and datastore counters |
| vROps | bare metal | **none** | history of hosts, clusters and datastores; alerts |
| PowerFlex | storage | **none** | volumes, pools, storage nodes, their IOPS and latency, rebuilds |

## 5. The options

| Option | What it is | For | Against |
| --- | --- | --- | --- |
| A. Skill + `govc` | a skill whose recipes run `govc` (one static Go binary) per vCenter | usable within days | the model holds vCenter credentials; raw JSON floods the context; nothing enforces read-only; the CPU and storage checks are many commands to get right in order |
| B. MCP only | typed read-only tools over pyVmomi, the vROps REST API and the PowerFlex REST API | read-only enforced; lookup and checks done once, correctly | no procedure for reading the results |
| **C. Both (recommended)** | the MCP for access and diagnosis, the skill for the procedure | each does what it is good at | two things to maintain |
| D. Adopt a community server | `vcenter-mcp`, `vSphere-MCP-Pro`, `mcvsphere`, `vcf-ops-mcp` | they exist | built for lifecycle (create, power, snapshot): exactly the actions this must not have; single vCenter; no console, log or contention diagnosis |

**Recommendation: C, built in the Sahara MCP's style** (package layout,
`pydantic-settings` config, stdio and Streamable HTTP, byte budgets,
concurrency limit). `govc` with a read-only account is useful in phase 0
to collect real examples before the server exists.

## 6. The tools

All read-only. Every result names the vCenter, the moref, the
`instanceUuid`, the creation time and the time it was read.

### 6.1 Finding

| Tool | Answers | API |
| --- | --- | --- |
| `list_vcenters` | the nine, reachable or not, their versions | `ServiceInstance.content.about` |
| `find_environment(env_id, vcenter=None)` | the folder(s) matching the env id, with full path, parent and VM count; on every vCenter when none is given; ambiguity reported, not resolved | `PropertyCollector` over folder names |
| `get_environment(vcenter, env_id)` | the environment's folder and every VM in it, with power state, Tools state, host, datastore, boot time | `ContainerView` on the folder + `PropertyCollector` |
| `get_vm(vcenter, env_id, vm_name)` | the VM's key | inside the env folder only |

### 6.2 Scanning: the other way in

Not every investigation starts from a Sahara error. "Look at `vc-04` and
find anything abnormal", "are there machines on these three vCenters that
booted more than 10 minutes ago and never came up?" are first-class
questions, answered on demand and read-only.

| Tool | Answers |
| --- | --- |
| **`scan(vcenters=[...] or all, checks=all, min_uptime_min=10)`** | every VM on the vCenters asked for, classified; the abnormal ones returned with their class, env folder, host and datastore, and grouped by vCenter, cluster, host, datastore and env, each group against its population ("29 of 210 VMs on `ds-17`") |
| `explain_group(scan_id, group)` | runs the CPU and storage checks for one group and compares it with the healthy VMs around it: what the stuck ones share that the rest do not |
| `diagnose_window(vcenters, since, until)` | the same for a past window, from events and counters, when the VMs may already be gone |

One `PropertyCollector` call per vCenter over a `ContainerView`, asking
only for what the checks need (`runtime.powerState`, `runtime.bootTime`,
`runtime.question`, `runtime.connectionState`, `guest.toolsRunningStatus`,
`guestHeartbeatStatus`, `guest.ipAddress`, `summary.quickStats`,
`runtime.host`, `datastore`, `parent`), so a scan of nine vCenters is
nine cheap calls, not thousands.

The checks, with thresholds in config:

| Check | Rule |
| --- | --- |
| `booted_not_up` | powered on, booted more than N minutes ago, Tools not running |
| `hung` | booted not up, CPU near zero |
| `busy_not_up` | booted not up, CPU busy: starved, spinning or boot-looping; the CPU and storage checks decide which |
| `boot_loop` | several resets or guest reboots in the last N minutes, from events |
| `blocked_on_question` | a pending VM question |
| `lost_heartbeat` | Tools were running, heartbeat now gray or red |
| `tools_flapping` | Tools running and not running in turn, from events and `vmware.log`: the "Tools keeps crashing" symptom |
| `shared_base_busy` | many VMs on one linked-clone base disk booting in the same minutes, with that disk's datastore slow |
| `inaccessible` | disconnected, inaccessible, orphaned or invalid |
| `overcommitted_host` | a host above the CPU demand threshold, with the VMs on it |
| `slow_datastore` | a datastore above the latency threshold, with the VMs on it |

A scan answers "what is wrong and where"; `explain_group` and
`diagnose_vm` on two or three representatives answer "why". The scan
picks the representatives, so the model does not diagnose 40 VMs one by
one.

### 6.3 The composite diagnoses

| Tool | Answers |
| --- | --- |
| **`diagnose_vm(vcenter, env_id, vm_name)`** or `diagnose_vm(key)` | the flow of section 3, step 2: machine, console, boot timeline (6.5), host, datastore, the rest of the environment, a finding |
| **`diagnose_environment(vcenter, env_id)`** | every VM of the environment classified, grouped by host and datastore, the CPU and storage checks for each group, a finding |

Each composite runs the checks in a fixed order, with thresholds in
config tuned on past incidents, so the answer does not depend on the
model remembering what to look at:

1. **The machine**: power, Tools, heartbeat, pending question, uptime,
   CPU use. "Booted 14 min ago, Tools not running, CPU at one full vCPU"
   is starved or spinning; "CPU near zero" is hung; a question is blocked.
2. **CPU**: the host's demand against capacity, the VM's ready time and
   co-stop during boot. Above thresholds: *CPU starvation*, hosts named.
3. **Storage**: the datastore's device, kernel and queue latency, IOPS,
   aborted commands and resets in the boot window; with PowerFlex
   configured, the pool and nodes behind it. Above thresholds: *storage
   saturation*, datastore and pool named. High queue latency with normal
   device latency points at the host's queue; high device latency points
   at PowerFlex.
4. **The rest of the environment and its hosts**: are the healthy VMs on
   other hosts or datastores? That is what makes the finding a cause rather
   than a coincidence.
5. **Neither**: CPU and storage healthy, so the guest itself: console,
   `vmware.log`, events. Said explicitly.

A third recurring cause, once found, becomes a sixth check.

### 6.4 The pieces, to drill into one finding

| Tool | Answers | API |
| --- | --- | --- |
| `get_vm_state(key)` | power, connection, pending question, uptime, boot time, firmware, snapshots | `runtime`, `config` |
| `get_vm_guest(key)` | Tools running and version status, heartbeat, guest IPs, guest OS | `guest`, `guestHeartbeatStatus` |
| `get_vm_console(key, captures=2, interval_s=10)` | the console as an image, plus text for a model without vision: black fraction, frozen or changing, OCR if an engine is installed | the `/screen?id=` endpoint; **not** `CreateScreenshot_Task`, which writes a PNG into the VM's datastore folder |
| `get_vm_events(key, since)` | power, reset, migration, HA, reconfigure, Tools and guest events; works for destroyed VMs | `EventManager.QueryEvents` |
| `get_vm_tasks(key, since)` | tasks against it, Sims' included | `TaskManager` collectors |
| `read_vm_log(key, which=0, grep, tail, since)` | `vmware.log` and the rotated `vmware-N.log` from before the reboot, filtered on the server | HTTPS `GET /folder/<path>?dcPath=&dsName=` |
| `get_vm_metrics(key, counters, since)` | ready time, co-stop, CPU use, disk latency for this VM | `PerfManager.QueryPerf` |
| `get_host_health(host, since)` | CPU demand and usage, memory, per-datastore latency, the VMs on it | `PerfManager`, `summary` |
| `get_datastore_health(ds, since)` | free space, accessibility, latency, IOPS, the VMs on it | same |
| `read_host_log(host, log, since, grep)` | `vmkernel`, `hostd` lines in the window: path failures, APD/PDL, latency warnings | `DiagnosticManager.BrowseDiagnosticLog` |

Logs are never returned whole: a `grep`, `tail` or time window is
required, results are capped, and the default `grep` is a list of lines
that matter in a boot hang, built from your own logs in phase 0.

Counters behind the CPU and storage checks (to confirm against your
vCenter's statistics level): `cpu.ready.summation`, `cpu.costop.summation`,
`cpu.demand.average`, `cpu.usage.average`; `disk.deviceLatency.average`,
`disk.kernelLatency.average`, `disk.queueLatency.average`,
`disk.numberReadAveraged.average`, `disk.numberWriteAveraged.average`,
`disk.commandsAborted.summation`, `disk.busResets.summation`;
`datastore.totalReadLatency.average`, `datastore.totalWriteLatency.average`.
Ready time is reported as a percentage per vCPU, not raw milliseconds.
vCenter keeps 20-second samples for about an hour and coarser rollups
after that; for older windows the checks use vROps and say so.

### 6.5 The boot timeline: what the logs can and cannot show

The question "did the machine try to boot and then the kernel timed out?"
has a precise answer, and it is "partly, and fully only if the template
cooperates".

**What `vmware.log` is.** The log of the VMX, the hypervisor process that
*runs* the VM, not of the guest. It sees the virtual hardware from the
outside. It does not see the guest kernel's messages: a kernel's "timed
out waiting for device", a hung task warning, a panic's text, a dracut
emergency shell, a Windows stop code go to the guest's screen and the
guest's own logs, never to `vmware.log`.

**What it does show, and what that lets you infer.** The guest's
progress through boot leaves marks on the virtual hardware, and the VMX
logs some of them. A timeline built from those marks says *how far* the
boot got:

| Stage | Mark in `vmware.log` (exact lines to confirm on your logs) | If the timeline stops here |
| --- | --- | --- |
| Power-on or reset | the power-on or reset itself, with a timestamp | the VM never started: the events and the host say why |
| Firmware (BIOS/EFI) | firmware messages, boot device attempts | no bootable disk, or the firmware stalled on storage |
| Bootloader and kernel start | the first disk reads and writes after the reset | the bootloader or the early kernel stalled: compare with the datastore latency at that minute |
| Kernel drivers loading | the guest's paravirtual drivers announcing themselves (VMXNET3 network, PVSCSI storage, SVGA graphics resolution change) | the kernel ran far enough to load drivers, then stopped: root filesystem, a device timeout, a panic |
| Tools start | Tools state and version reported, the guest RPC channel opening | Tools started: the problem is after boot, or a timeout upstream |
| Faults | a triple fault, a monitor panic, a guest-requested reset | the guest crashed hard enough for the hypervisor to see it |
| Storage trouble | SCSI resets, aborted commands, long stuns | the I/O path stalled under the guest |

So `vmware.log` can say "the kernel loaded its drivers at 02:14:40 and
then Tools never started", and with the datastore latency at that minute
and the console, the diagnosis is usually clear. It cannot quote the
kernel's own error.

**Four sources together give the full picture:**

1. **`vmware.log`**: the stages above, and the rotated `vmware-N.log` for
   the boot before the reboot.
2. **The console**: if the guest prints text, the last screen *is* the
   kernel's or the bootloader's last message, and OCR turns it into text
   (a dracut timeout, a panic, "waiting for root device"). A black screen
   is weaker: it may be a hang, a graphical splash hiding the messages, or
   a blanked display. Two captures show frozen or changing.
3. **The VM's own counters for its short life**: disk reads and CPU over
   the boot. Busy CPU and steady I/O is a slow boot; CPU near zero and no
   I/O after the bootloader is a guest waiting on something that will not
   come.
4. **The host's `vmkernel` log**: "performance has deteriorated" latency
   warnings and path errors for the datastore's device, at the minute the
   timeline stopped.

**Windows first.** Most of the fleet is Windows, from Vista up to the
current versions, and it causes most of the trouble. What that changes:

- **The console says more on Windows than on Linux.** Windows draws its
  state on the screen, and OCR reads it: the spinning boot dots, "Working
  on updates", "Getting devices ready", "Preparing Automatic Repair",
  "Scanning and repairing drive", a Windows Boot Manager error with its
  code, a blue screen with its stop code. Each is a different diagnosis,
  and the screenshot is often the single most useful piece of evidence
  for a Windows VM that did not come back. The screens differ by version
  (Vista and 7 show "Starting Windows" and a progress bar, 8 and later the
  spinning dots; the blue screen's layout changed too), so the OCR and the
  skill must recognise each generation's screens; that is tested in phase
  0 on real captures from several versions.
- **A black screen on Windows** is usually early boot before the display
  is initialised, or a hang before the logon screen; two captures and the
  VM's CPU and disk counters separate a slow boot from a hang.
- **Not every "did not come back" is a fault.** Windows Update, a disk
  check or driver setup may run on the way up, take minutes, and outlast
  the timeout that raises the Tools error; the console shows which. On a
  CPU-starved host or a saturated base disk, these slow Windows steps are
  where the starvation shows.
- **"Tools keeps crashing."** Tools on Windows is a service started late
  in boot. vCenter cannot see why the service died (that is in the guest's
  event log), but it can see the pattern: Tools running, then not, then
  running again, in events and `vmware.log`. A flapping Tools on a
  starved host and on a healthy host are different findings.

**Getting the guest's own words**, read-only on our side, with a change
to the templates on theirs:

- **Windows: Emergency Management Services on a virtual serial port**
  that writes to a file in the VM's datastore folder (`bcdedit /ems on`
  and `/emssettings`, set in the template). With EMS on, Windows can write
  its stop information on a blue screen to that port, so it lands in a
  file the MCP reads like `vmware.log`, even when nobody saw the console.
  EMS is a Windows Server feature first; whether it does this on the
  desktop versions in the fleet (Vista to 11) is unknown and checked in
  the lab. If it does not, the screenshot is the evidence for those
  versions. Optional either way.
- **Linux: the kernel console on the same kind of serial port**
  (`console=ttyS0` alongside the normal one), and no `quiet` or graphical
  splash, so every kernel line, timeouts and panics included, is in the
  file and on the screen.
- **Crash dumps** are written inside the guest's disk, which vCenter
  cannot read. If the VM later comes back and Sahara collects the dump as
  a monitor, the Sahara MCP's dump workflow takes over; the skill points
  there.

These are template changes owned by whoever builds the templates; the MCP
only reads what they produce. Without them, the timeline, the console and
the counters are what there is, and the diagnosis says so.

| Tool | Answers |
| --- | --- |
| **`get_boot_timeline(key)`** | the stages reached, with times, from `vmware.log`, the VM's counters, the console and, if present, the serial log; the last stage reached and what was happening on the host and datastore at that minute |
| `read_serial_log(key, grep, tail)` | the guest's serial console file, when the template has one |

### 6.6 vROps

For the long-lived things (hosts, clusters, datastores); a 30-minute VM
barely registers.

| Tool | Answers |
| --- | --- |
| `vrops_get_stats(resource, stat_keys, since, until)` | days or weeks of a host's, cluster's or datastore's counters |
| `vrops_compare_window(resource, window, baseline_days)` | the incident window against the same window on previous days: spike, or normal for this cluster? |
| `vrops_get_alerts(resource, since)` | alerts and symptoms on it and its parents |

### 6.7 PowerFlex (optional)

vCenter sees PowerFlex only as a slow device. Which pool or storage node
was saturated, whether a rebuild or rebalance was running, and which
volumes drove the IOPS is visible only from PowerFlex's REST API (gateway
or PowerFlex Manager; endpoints confirmed on your version). Read-only:

| Tool | Answers |
| --- | --- |
| `powerflex_map_datastore(ds)` | the volume, storage pool, protection domain and storage nodes behind a datastore |
| `powerflex_get_stats(object, since)` | IOPS, bandwidth and latency of a volume, pool or node |
| `powerflex_get_activity(since)` | rebuilds, rebalances, degraded or failed devices in the window |
| `powerflex_top_volumes(pool, since)` | the volumes that drove the IOPS on a pool: the noisy neighbour |

Without it, the storage check stops at "datastore latency high" and says
the PowerFlex side was not checked.

## 7. Output shapes, for GLM 5.3

The model reading these results is not a frontier model; the server
carries more of the reasoning:

- **Composite first.** The skill starts every investigation with
  `diagnose_vm` or `diagnose_environment`; the pieces are for drilling in.
- **Findings first, raw values after**, so a model that reads only the
  first lines still gets the answer.
- **Missing data said explicitly**: "no events in window", "counters not
  kept at this statistics level", "PowerFlex not configured", "VM
  destroyed; diagnosis from events and host counters only".
- **Times in UTC, with the clock named.** Sahara, Sims, vCenter, ESXi,
  vROps and PowerFlex keep their own clocks.
- **No vision needed**: the screenshot also comes back as text.
- **Bounded**, the way the Sahara MCP bounds its payloads.

## 8. The skill: `vm-incident`

1. **Two entries.** From a Sahara error: the error's vCenter, machine and
   env id → `diagnose_vm`. From a question about the fleet: `scan` → the
   groups → `explain_group` → `diagnose_vm` on the representatives.
   **The ladder** from a Sahara error: Sahara Tools error (vCenter,
   machine, env id, time) → `diagnose_vm` → if the rest of the environment is affected,
   `diagnose_environment` → if many environments failed in the same
   window, `diagnose_window` → vROps for the history of the hosts or
   datastores named → PowerFlex if storage was named → Sims logs for what
   Sims did and how long it waited → verdict.
2. **The cause is shared until shown otherwise.** Check the host and the
   storage before explaining the guest; check the environment's healthy
   VMs before blaming the host or datastore they share.
3. **Never identify by name** outside the environment folder; carry the
   key from the first call to the last.
4. **Concepts, not constants** (section 2.1): find the env folder, the
   log fields and the vCenter's kind from the data each time; report an
   inconsistency as a finding.
5. **The causes and their evidence**:

   | Cause | Evidence for | Evidence against |
   | --- | --- | --- |
   | ESXi CPU overcommit | affected VMs on hosts above 100% demand; high ready time during boot; CPU busy, console changing | hosts below capacity; ready time low |
   | PowerFlex saturation | affected VMs share datastores on one pool; device latency and pool IOPS high in the boot window; a rebuild or a noisy volume | same pool, same window, healthy VMs booted |
   | Other storage trouble (APD/PDL, paths) | `vmkernel` path errors in the window | none |
   | Datastore full | free space near 0; a pending question about disk space | space healthy |
   | Pending VM question | `runtime.question` set | none |
   | Guest hang in early boot | CPU near zero; console black and frozen across captures; `vmware.log` reset then nothing from the guest; host and storage healthy | console changing; Tools came up |
   | Guest booted, Tools did not start | console at a login prompt or guest IPs reported; Tools not running; host and storage healthy | Tools running |
   | Linked-clone boot storm | many clones of one base disk booting in the same minutes; latency on the base disk's datastore high; clones of other bases fine | clones of the same base booted fine at the same time |
   | Windows still working (updates, disk check, driver setup) | the console shows updates, "Getting devices ready" or a disk scan; CPU and disk busy | console at the logon screen |
   | Windows crashed or cannot boot | the console or the EMS serial log shows a stop code, Automatic Repair, or a Boot Manager error | console at the logon screen |
   | Tools flapping | Tools running and not running in turn; check whether the host was starved at those moments | Tools steady |
   | Something else reset or moved it | HA, migration or reset events not from Sims | none |

6. **Starved is not hung.** A VM still booting on an overcommitted host
   is a timeout in Sims or Sahara, not a broken VM; the verdict says
   which.
7. **Correlation rules**: a shared timestamp is not a cause; name the
   evidence for each claim, the competing explanation, and the check that
   separates them.
8. **Evals that bait the failures**: looking up the machine by name
   across vCenters and finding another environment's VM; expecting a fixed
   folder path or log field and missing the env when the layout differs;
   blaming the guest while its host sits at 120%; blaming the host while
   the environment's VMs on other hosts are equally stuck; calling a
   slowly booting VM hung, or a Windows VM still installing updates
   broken; blaming one host or datastore when the stuck VMs share a
   linked-clone base disk; trusting one black screenshot without a second.

## 9. Security

- **Read-only by construction, whatever the account can do.** The
  accounts available can write. The server therefore enforces read-only
  itself and does not rely on the account: it calls only an allowlist of
  read methods (`PropertyCollector` retrieval, `QueryEvents`, task
  history, `QueryPerf`, `BrowseDiagnosticLog`, `SearchDatastore_Task` and
  HTTPS `GET` on `/folder` and `/screen`), and a test fails if any other
  vSphere method is reachable from a tool. `SearchDatastore_Task` is a
  task but writes nothing; no method that changes a VM, a host, a folder
  or a datastore file is in the list.
- **And, where possible, a read-only role too.** With a write account a
  dedicated service account with a custom read-only role (read inventory,
  console screen read, datastore browse and file read, diagnostics) can
  be created, so the guarantee holds twice: in code and in vCenter. The
  exact privilege per tool, and that the console route needs nothing that
  writes, are confirmed in the lab.
- **Why the agent never gets `govc` with these credentials**: a model
  with a shell and a write account can run any command, read-only skill
  or not. The skill's `govc` recipes are for a person in phase 0; the
  agent's access goes through the MCP.
- **The same for vROps and PowerFlex**: read-only API users.
- **TLS verified** against your internal CA, never turned off.
- **Credentials only in the server's environment**, never in tool
  arguments or results; `.vmx` contents and logs redacted (guestinfo can
  carry secrets).
- **Load**: one session per vCenter, a fixed list of properties per call,
  a concurrency limit per vCenter, a few seconds of caching.
- **Audit log** of every call.

## 10. Phases

| Phase | Builds | Done when |
| --- | --- | --- |
| **0. Collect** (days) | read-only `govc` runs against an affected environment during a real incident, plus the logs of the two past ones | the thresholds and the `vmware.log` / `vmkernel` lines of a starved and a hung boot are on file |
| **1. Scan, lookup, diagnose** | 6.1–6.5 (`scan`, `diagnose_vm`, `diagnose_environment`, `get_boot_timeline`) | a Sahara Tools error taken to the right machine, and a scan of the nine vCenters, each ending in a correct finding on the next live incident |
| **2. vROps + PowerFlex + `diagnose_window`** | 6.6, 6.7, past windows | the CPU incident and the PowerFlex incident each named, including for windows older than an hour |
| **3. Skill, full** | section 8 with evals | evals pass with GLM 5.3 in your client |

## 11. Open questions

1. **A few real examples, for the lab only**: an env folder's path on
   each kind of vCenter (environments and projects), and a Sahara Tools
   error record. They test that discovery finds them; nothing is
   hard-coded from them (section 2.1).
2. **How the Sahara log names the vCenter**: a hostname, or a short name
   that has to be matched to one of the nine?
3. **vCenter and vROps versions**, the statistics level, and the event
   retention setting.
4. **The two past incidents**: dates, windows, the hosts at ~120%, the
   PowerFlex pool. They tune the thresholds and become the first test
   cases.
5. **PowerFlex**: version, gateway or PowerFlex Manager, a read-only API
   user, and whether vROps already has a PowerFlex management pack.
6. **How long Sims and Sahara wait for Tools after a reboot**: the point
   where starved becomes an error.
7. **Does your GLM 5.3 client pass image content** from an MCP result to
   the model? *Default: no; the text form of the screenshot carries it.*
8. ~~Accounts~~: available, with write access; read-only is enforced by the server (section 9), and a read-only role created where possible.
9. **Linked clones**: are the base disks per template, or replicas per
   datastore? How many clones share one base at peak? Answerable from the
   lab data in phase 0; nothing waits on it.
10. **Later, optional**: a serial port writing to a file in the templates,
    with EMS for Windows and the kernel console for Linux (section 6.5),
    once the lab shows what EMS writes on the desktop versions.

## 12. What was built

The `vsphere_triage` package (pydantic-settings, stdio and
Streamable HTTP, bounded results, ruff with every rule):

- **Read-only by construction.** `ReadOnlyStub` refuses any vSphere method off
  a 13-method list before sending it; HTTP is GET only; the console is read
  through `/screen`, never `CreateScreenshot_Task`. A test proves every call
  the tools make is on the list, and another tries six kinds of write through
  a live session and sees each refused.
- **Both ways in.** `diagnose_vm` from a Sahara error (vCenter by any spelling,
  env id, machine name inside its folder); `scan` / `explain_group` /
  `diagnose_window` from a question about the fleet.
- **Discovery, not constants.** Environment folders found by name under any
  parent and reported with their path; ambiguity reported; group values
  qualified by vCenter.
- **The two known causes checked first**: CPU ready per vCPU and host demand
  against capacity; datastore, device and queue latency. The healthy VMs
  beside a stuck one are used as evidence for or against each cause.
- **Linked clones**: disk chains read, VMs grouped by base disk.
- **The boot**: a timeline from `vmware.log` (ESXi 6 and 7+ formats), rotated
  logs listed, EMS and Linux serial consoles read when present (stop codes
  mapped to the layer they usually point at), the console reduced to words.
- **vROps** (when configured): find, stat keys, stats, window against previous
  days, alerts.

Tested: 65 unit tests, 35 integration tests against `vmware/vcsim` built
into an environments-kind and a projects-kind vCenter (linked clones, hung
and busy Windows VMs, a question, a boot loop, an EMS stop code, a Linux soft
lockup, an env id on both vCenters, names reused across environments). The
simulator's random counters are replaced by controlled ones; it has no
`/screen` and no host logs, so those paths are tested as unavailable.

Not built: the PowerFlex adapter (section 6.7; no simulator, and its API
version is question 5), and the skill (section 8). `get_environment` became
part of `find_environment` and `diagnose_environment`.

